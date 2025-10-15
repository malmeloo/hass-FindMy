{ pkgs ? import <nixpkgs> {} }:

let
  unstable = import (fetchTarball https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz) { };
in
pkgs.mkShell {
  packages = with pkgs; [
    (python312.withPackages (ps: with ps; [virtualenv]))
    unstable.uv
    gh
  ];

  shellHook = ''
  if [[ -d .venv/ ]]; then
    source .venv/bin/activate
  fi
  '';
}