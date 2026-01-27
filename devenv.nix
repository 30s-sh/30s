{pkgs, ...}: {
  dotenv.enable = true;

  packages = [
    pkgs.changie
    pkgs.doctl
    pkgs.doppler
    pkgs.gh
    pkgs.git
    pkgs.just
    pkgs.sqlx-cli
  ];

  languages = {
    rust = {
      enable = true;
      channel = "stable";
    };
  };

  services = {
    postgres = {
      enable = true;
      listen_addresses = "127.0.0.1";
    };

    redis = {
      enable = true;
    };

    mailpit = {
      enable = true;
    };
  };

  git-hooks.hooks = {
    # Nix

    alejandra.enable = true;

    # Rust

    cargo-check.enable = true;
    rustfmt.enable = true;

    clippy = {
      enable = true;
      entry = "cargo clippy -- -D warnings";
      pass_filenames = false;
      stages = ["pre-commit"];
    };

    test = {
      enable = true;
      entry = "cargo test";
      pass_filenames = false;
      stages = ["pre-push"];
    };
  };
}
