// Wire
// ====
// TCP on bytes: a List<U32> of octets in and out. After bend-kit-wire (MIT-0).

function gw_list(b, n) {
  let xs = { $: "Nil" };
  for (let i = n; i > 0; i -= 1) {
    xs = { $: "Con", head: b[i - 1], tail: xs };
  }
  return xs;
}

function wire_recv(socket, max, k) {
  const sys = io_sys();
  const fd = socket;
  const b = new Uint8Array(Math.max(Number(max), 1));
  const again = sys.mac ? 35 : 11;
  const go = () => {
    const n = Number(sys.recv(fd, sys.ptr(b), Number(max), 0));
    if (n < 0) {
      const code = sys.errno();
      if (code === again) {
        io_park_on(fd, false, k, go);
        return undefined;
      }
      return io_tup(socket, io_fail(code));
    }
    return io_tup(socket, io_done(gw_list(b, n)));
  };
  return go();
}

function wire_recv_need() {
  return { read: true };
}

// wire_recv with a deadline, as Base's TCP.poll: None past it
function wire_recv_timeout(socket, max, ms, k) {
  const sys = io_sys();
  const fd = socket;
  const b = new Uint8Array(Math.max(Number(max), 1));
  const again = sys.mac ? 35 : 11;
  const at = performance.now() + Number(ms);
  const go = () => {
    const n = Number(sys.recv(fd, sys.ptr(b), Number(max), 0));
    if (n >= 0) {
      return io_tup(socket, io_done({ $: "Some", value: gw_list(b, n) }));
    }
    const code = sys.errno();
    if (code !== again) {
      return io_tup(socket, io_fail(code));
    }
    if (performance.now() >= at) {
      return io_tup(socket, io_done({ $: "None" }));
    }
    io_park_on(fd, false, k, go, at);
    return undefined;
  };
  return go();
}

function wire_send(socket, data, k) {
  const sys = io_sys();
  const fd = socket;
  const bytes = [];
  for (let xs = data; xs.$ === "Con"; xs = xs.tail) {
    bytes.push(xs.head);
  }
  if (bytes.some((x) => x > 255)) {
    return io_tup(socket, io_fail(22));
  }
  const b = Uint8Array.from(bytes);
  const again = sys.mac ? 35 : 11;
  const go = (at) => {
    while (at < b.length) {
      const part = b.subarray(at);
      const n = Number(sys.send(fd, sys.ptr(part), part.length, 0));
      if (n < 0) {
        const code = sys.errno();
        if (code === again) {
          io_park_on(fd, true, k, () => go(at));
          return undefined;
        }
        return io_tup(socket, io_fail(code));
      }
      at += n;
    }
    return io_tup(socket, io_done({ $: "Unit" }));
  };
  return go(0);
}

// wire_send with a deadline: fails ETIMEDOUT (60 on macOS, 110 on Linux)
// when the socket stays full past it
function wire_send_timeout(socket, data, ms, k) {
  const sys = io_sys();
  const fd = socket;
  const bytes = [];
  for (let xs = data; xs.$ === "Con"; xs = xs.tail) {
    bytes.push(xs.head);
  }
  if (bytes.some((x) => x > 255)) {
    return io_tup(socket, io_fail(22));
  }
  const b = Uint8Array.from(bytes);
  const again = sys.mac ? 35 : 11;
  const end = performance.now() + Number(ms);
  const go = (at) => {
    while (at < b.length) {
      const part = b.subarray(at);
      const n = Number(sys.send(fd, sys.ptr(part), part.length, 0));
      if (n < 0) {
        const code = sys.errno();
        if (code === again) {
          if (performance.now() >= end) {
            return io_tup(socket, io_fail(sys.mac ? 60 : 110));
          }
          io_park_on(fd, true, k, () => go(at), end);
          return undefined;
        }
        return io_tup(socket, io_fail(code));
      }
      at += n;
    }
    return io_tup(socket, io_done({ $: "Unit" }));
  };
  return go(0);
}

// TCP.connect with a deadline: ETIMEDOUT (60 on macOS, 110 on Linux) when
// the socket is not writable by then
function wire_connect_timeout(host, port, ms, k) {
  const sys = io_sys();
  const at = io_addr(host, Number(port));
  if (at === null) {
    return io_fail(22);
  }
  const fd = sys.socket(2, 1, 0);
  if (fd < 0) {
    return io_fail(sys.errno());
  }
  const deadline = performance.now() + Number(ms);
  const end = (code) => {
    if (code !== 0) {
      sys.close(fd);
      return io_fail(code);
    }
    return io_done(fd);
  };
  const error = () => {
    const v = new Int32Array([0]);
    const l = new Uint32Array([4]);
    return sys.getsockopt(fd, sys.mac ? 0xffff : 1, sys.mac ? 0x1007 : 4,
      sys.ptr(v), sys.ptr(l)) < 0 ? sys.errno() : v[0];
  };
  const set = sys.fcntl(fd, 4, sys.fcntl(fd, 3, 0) | (sys.mac ? 4 : 0x800));
  const ok = set >= 0 && sys.connect(fd, sys.ptr(at), 16) >= 0;
  const code = ok ? 0 : sys.errno();
  if (code !== (sys.mac ? 36 : 115)) {
    return end(code);
  }
  io_park_on(fd, true, k, () => end(performance.now() >= deadline ? (sys.mac ? 60 : 110) : error()), deadline);
  return undefined;
}

// TCP.accept with a deadline: None past it
function wire_accept_timeout(listener, ms, k) {
  const sys = io_sys();
  const lfd = listener;
  const again = sys.mac ? 35 : 11;
  const at = performance.now() + Number(ms);
  const go = () => {
    const fd = sys.accept(lfd, null, null);
    if (fd < 0) {
      const code = sys.errno();
      if (code !== again) {
        return io_tup(listener, io_fail(code));
      }
      if (performance.now() >= at) {
        return io_tup(listener, io_done({ $: "None" }));
      }
      io_park_on(lfd, false, k, go, at);
      return undefined;
    }
    if (sys.fcntl(fd, 4, sys.fcntl(fd, 3, 0) | (sys.mac ? 4 : 0x800)) < 0) {
      const code = sys.errno();
      sys.close(fd);
      return io_tup(listener, io_fail(code));
    }
    return io_tup(listener, io_done({ $: "Some", value: fd }));
  };
  return go();
}

let gw_stop = false;

function wire_on_stop() {
  process.on("SIGTERM", () => { gw_stop = true; });
  process.on("SIGINT", () => { gw_stop = true; });
  return { $: "Unit" };
}

function wire_stopping() {
  return gw_stop ? 1 : 0;
}

let gw_live = 0;

function wire_live(d) {
  gw_live = (gw_live + Number(d)) >>> 0;
  return gw_live;
}
