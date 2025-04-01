{
  description = "goto.py - A script for managing incident cases";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python3;
        pythonPackages = python.pkgs;
      in
      {
        packages.default = pythonPackages.buildPythonApplication {
          pname = "timeliner";
          version = "0.1.0";
          src = ./.;

          propagatedBuildInputs = with pythonPackages; [
            colorama
            click
          ];

          nativeBuildInputs = with pythonPackages; [
            setuptools
            pytest
            pytest-mock
          ];

          checkPhase = ''
            pytest
          '';

          meta = with pkgs.lib; {
            description = "Timeliner";
            homepage = "https://github.com/nbareil/timeliner.py";
            license = licenses.mit;
            maintainers = [ "Nicolas Bareil" ];
          };
        };

        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            python
            pythonPackages.colorama
            pythonPackages.click
            pythonPackages.pytest
            pythonPackages.pytest-mock
            pythonPackages.setuptools
            tmux
          ];
        };
      }
    );
}
