"""Server credentials, handshake and connection owners are affine."""
from pathlib import Path
import subprocess
import tempfile


def main():
    root=Path(__file__).resolve().parent
    prefix=('import Base\nimport ../bend_tls_server.bend as S\n'
            'import ../bend_tls_client.bend as C\nimport ../tls_server_flight.bend as F\n'
            'import ../crypto/credential.bend as K\n\n'
            'def main() -> IO(Unit):\n  IO.pure(Unit,Unit{})\n\n')
    # Probe files are directly below wire, so credential import is two levels up.
    prefix=prefix.replace('../crypto/credential.bend','../../crypto/credential.bend')
    rows=[
        ('close',True,'def example(c: S.Connection) -> IO(Unit):\n  S.close(c)\n'),
        ('deadline',True,'def example(c: S.Connection) -> S.Connection:\n  S.deadline(c,1n)\n'),
        ('accept',True,'def example(s: Socket, c: S.Config) -> IO(Result<&2,&1,C.Error,S.Connection>):\n  S.accept(s,c)\n'),
        ('connection-copy',False,'def bad(+c: S.Connection) -> S.Connection & S.Connection:\n  (c,c)\n'),
        ('config-copy',False,'def bad(+c: S.Config) -> S.Config & S.Config:\n  (c,c)\n'),
        ('received-copy',False,'def bad(+r: S.Received) -> S.Received & S.Received:\n  (r,r)\n'),
        ('flight-copy',False,'def bad(+r: F.Flight) -> F.Flight & F.Flight:\n  (r,r)\n'),
        ('send-reuse',False,'def bad(+c: S.Connection) -> IO(Result<&2,&1,C.Error,S.Connection>) & IO(Result<&2,&1,C.Error,S.Connection>):\n  (S.send(c,[]),S.send(c,[]))\n'),
    ]
    with tempfile.TemporaryDirectory(prefix='server-types-',dir=root) as td:
        for name,accepted,body in rows:
            source=Path(td)/(name+'.bend')
            source.write_text(prefix+body)
            result=subprocess.run(['bend',str(source)],capture_output=True,text=True,timeout=30)
            assert (result.returncode==0)==accepted,(name,result.stdout,result.stderr)
            if not accepted:
                assert any(word in result.stderr+result.stdout for word in ('Data','consumed','linear','affine')),(name,result.stderr)
    print(f'server ownership: {len(rows)}/{len(rows)}')


if __name__=='__main__':
    main()
