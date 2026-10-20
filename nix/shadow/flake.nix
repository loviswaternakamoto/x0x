{
  description = "Pinned development shell for the offline BNRoSe/x0x shadow experiment";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }: let
    systems = [ "x86_64-linux" "aarch64-linux" ];
  in {
    devShells = nixpkgs.lib.genAttrs systems (system: let
      pkgs = import nixpkgs { inherit system; };
    in {
      default = pkgs.mkShell {
        packages = with pkgs; [ rustup pkg-config openssl clang cmake perl git time util-linux ];
        LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
        shellHook = ''
          echo "BNRoSe shadow: use cargo +1.95.0; no daemon or live mesh is started."
        '';
      };
    });
  };
}
