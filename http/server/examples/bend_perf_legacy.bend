import Base
import ../server.bend as Server
import ./bend_perf_app.bend as App

def main() -> IO(Unit):
  do IO<Unit>:
    cfg : Server.Config <- Server.from_env(Server.default(8090))
    Server.serve(~App.app,cfg)
