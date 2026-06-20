{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = [ pkgs.nodejs_22 pkgs.chromium ];
  shellHook = ''
    export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
    export CHROMIUM_EXECUTABLE_PATH="${pkgs.chromium}/bin/chromium"
  '';
}
