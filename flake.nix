{
  description = "timeliner.py - Browse bodyfile like a champ";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python3;

        # Runtime dependencies, mirroring the PEP 723 header in timeliner.py.
        runtimeDeps = ps: with ps; [
          click
          colorama
          tzdata
        ];

        timeliner = python.pkgs.buildPythonApplication {
          pname = "timeliner";
          version = "2.0";
          src = ./.;

          # The project is a single-file script with no setup.py/pyproject.toml.
          format = "other";

          propagatedBuildInputs = runtimeDeps python.pkgs;
          nativeCheckInputs = with python.pkgs; [ pytestCheckHook ];

          # Replace the `uv run` shebang with the Nix Python interpreter so the
          # installed program is runnable from the store.
          postPatch = ''
            substituteInPlace timeliner.py \
              --replace-fail '#! /usr/bin/env -S uv run -q' '#!${python.interpreter}'
          '';

          installPhase = ''
            runHook preInstall
            install -Dm755 timeliner.py $out/bin/timeliner
            install -Dm644 timeliner.py \
              $out/${python.sitePackages}/timeliner.py
            runHook postInstall
          '';

          doCheck = true;
          enabledTestPaths = [ "timeliner_test.py" ];

          meta = with pkgs.lib; {
            description = "Browse bodyfile like a champ";
            homepage = "https://github.com/nbareil/timeliner";
            license = licenses.mit;
            maintainers = [ "Nicolas Bareil" ];
            mainProgram = "timeliner";
          };
        };
      in
      {
        packages.default = timeliner;
        packages.timeliner = timeliner;

        apps.default = flake-utils.lib.mkApp {
          drv = timeliner;
        };

        # `nix flake check` builds the package and runs the test suite.
        checks.default = timeliner;

        devShells.default = pkgs.mkShell {
          packages = [
            (python.withPackages (ps: runtimeDeps ps ++ [ ps.pytest ]))
            pkgs.uv
          ];
        };

        formatter = pkgs.nixpkgs-fmt;
      }
    );
}
