{
  description = "Development tools for Sofka plugin packages";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pythonAttr = "python" + builtins.replaceStrings [ "." "\n" ] [ "" "" ] (builtins.readFile ./.python-version);
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          python = pkgs.${pythonAttr};
          common = {
            packages = with pkgs; [
              cargo
              rustc
              clippy
              rustfmt
              rust-analyzer
              python
              uv
              git
              jq
              nixpkgs-fmt
            ];
            UV_PYTHON = "${python}/bin/python3";
            UV_PYTHON_DOWNLOADS = "never";
            UV_LINK_MODE = "copy";
          } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
            LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib ];
          };
        in
        {
          default = pkgs.mkShell common;
          tools = pkgs.mkShell (common // {
            packages = common.packages ++ (with pkgs; [ kubectl cmctl oha popeye trivy ]);
          });
        });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixpkgs-fmt);
    };
}
