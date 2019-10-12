{ pkgs, LORRI_ROOT, BUILD_REV_COUNT, RUN_TIME_CLOSURE }:
let

  lorriBinDir = "${LORRI_ROOT}/target/debug";

  inherit (import ./execline.nix { inherit pkgs; })
    writeExecline;

  inherit (import ./lib.nix { inherit pkgs writeExecline; })
    allCommandsSucceed
    pathAdd
    getBins
    ;

  bins = getBins pkgs.shellcheck [ "shellcheck" ]
      // getBins pkgs.gitMinimal [ "git" ]
      // getBins pkgs.mandoc [ "mandoc" ]
      // getBins pkgs.cargo [ "cargo" ]
      // getBins pkgs.gnused [ "sed" ]
      // getBins pkgs.bats [ "bats" ]
      // getBins pkgs.coreutils [ "test" "echo" "cat" "mkdir" "mv" "touch" ]
      ;

  inherit (import ./sandbox.nix { inherit pkgs writeExecline; })
    runInEmptyEnv;

  # shellcheck a file
  shellcheck = file: writeExecline "lint-shellcheck" {} [
    "cd" LORRI_ROOT
    "if" [ bins.echo "shellchecking ${file}" ]
    bins.shellcheck "--shell" "bash" file
  ];

  cargoEnvironment =
    # we have to add the bin to PATH,
    # otherwise cargo doesn’t find its subcommands
    [ (pathAdd "prepend") (pkgs.lib.makeBinPath [
        # all cargo executables call themselves recursively, smh
        pkgs.rustc
        pkgs.gcc
        pkgs.rustfmt
        pkgs.clippy
        pkgs.cargo
      ])
      "export" "BUILD_REV_COUNT" (toString BUILD_REV_COUNT)
      "export" "RUN_TIME_CLOSURE" RUN_TIME_CLOSURE ];

  cargo = name: setup: args:
    writeExecline name {} (cargoEnvironment ++ setup ++ [ bins.cargo ] ++ args);

  # the CI tests we want to run
  # Tests should not depend on each other (or block if they do),
  # so that they can run in parallel.
  # If a test changes files in the repository, sandbox it.
  tests = {

    shellcheck =
      let files = [
        "nix/bogus-nixpkgs/builder.sh"
        "src/ops/direnv/envrc.bash"
      ];
      in {
        description = "shellcheck ${pkgs.lib.concatStringsSep " and " files}";
        test = allCommandsSucceed "lint-shellcheck-all" (map shellcheck files);
      };

    cargo-fmt = {
      description = "cargo fmt was done";
      test = cargo "lint-cargo-fmt" [] [ "fmt" "--" "--check" ];
    };

    cargo-test = {
      description = "run cargo test";
      test = cargo "cargo-test"
        # the tests need bash and nix and direnv
        [ (pathAdd "prepend") (pkgs.lib.makeBinPath [ pkgs.coreutils pkgs.bash pkgs.nix pkgs.direnv ]) ]
        [ "test" ];
    };

    cargo-clippy = {
      description = "run cargo clippy";
      test = cargo "cargo-clippy" [ "export" "RUSTFLAGS" "-D warnings" ] [ "clippy" ];
    };

    # TODO: it would be good to sandbox this (it changes files in the tree)
    # but somehow carnix needs to compile the whole friggin binary in order
    # to generate a few measly nix files …
    carnix = {
      description = "check carnix up-to-date";
      test = writeExecline "lint-carnix" {}
        (cargoEnvironment
        ++ [
          (pathAdd "prepend") (pkgs.lib.makeBinPath [ pkgs.carnix ])
          "if" [ pkgs.runtimeShell "${LORRI_ROOT}/nix/update-carnix.sh" ]
          bins.git "diff" "--exit-code"
        ]);
    };

    ci-script = {
      description = "check ci script was generated";
      test = writeExecline "ci-script" {} [
        "if" [ (import ../../.github/workflows/ci.nix { inherit pkgs; }) ]
        bins.git "diff" "--quiet" "--" "${LORRI_ROOT}/.github/workflows/ci.yml"
      ];
    };


    lint-manpage = offlineCheck.test {
      name = "lint-manpage";
      description = "lint the manpage";
      test = { ok, err }: pkgs.writers.writeDash "mandoc-lint" ''
        lint_warnings="$(
          ${bins.mandoc} -Tlint < ${../../lorri.1} \
            | ${bins.sed} -e '/referenced manual not found/d'
        )"

        # only succeed if theer were no warnings
        if [ ! -z "$lint_warnings" ]; then
          echo "$lint_warnings" >&2
          ${err}
        else
          ${ok}
        fi
      '';
    };

  };

  # An offline check is a check that can be run inside a nix build.
  # But instead of crashing the nix build, it will write the result to $out
  # and generate a test runner that will just print the script.
  # This means we don’t have to run the check on CI every time
  # if the nix build inputs didn’t change.
  offlineCheck = {

    # create an offline check test
    # the test is passed `{ ok, err }`, which are the commands to call
    # at the end, depending on whether the test succeeded or failed.
    test = { name, description, test }: {
      inherit description;
      test =
        let genResult = pkgs.runCommandLocal "${name}-result" {} ''
          mkdir -p "$out"
          set +e
          ${test { ok = offlineCheck.ok; err = offlineCheck.err; }} \
            2> "$out/stderr"
          code=$?
          set -e
          # should the test exit 123 by chance, this check will not work, but better than nothing
          # We require the use of ok/err, otherwise it’s too easy to accidentally
          # succeed tests in scripts (e.g. forgot "set -e").
          if [ ! $code -eq 123 ]; then
            echo "offlineCheck: please call ok or err in order to finish the test" >&2
            echo "test finished with exit code: $code" >&2
            exit 100
          fi
        '';
        in writeExecline name {} [
          offlineCheck.checkResult genResult
        ];
    };

    # end the test successfully
    ok = writeExecline "offline-check-ok" {} [
      "importas" "-ui" "out" "out"
      "if" [ bins.mkdir "-p" "$out" ]
      "if" [ bins.touch "\${out}/ok" ]
      "exit" "123"
    ];
    # end the test with an error, the output of stderr will be the test result
    err = writeExecline "offline-check-ok" {} [
      "importas" "-ui" "out" "out"
      "if" [ bins.echo "The test signaled an error, finishing." ]
      "if" [ bins.touch "\${out}/err" ]
      "exit" "123"
    ];

    # check whether the result of the test was successful or not
    checkResult = writeExecline "offline-check-getResult" { readNArgs = 1; } [
      "ifelse"
          [ bins.test "-e" "\${1}/err" ]
        [ "if" [ "redirfd" "-r" "0" "\${1}/stderr" bins.cat ]
          "exit" "1"
        ]
      "ifelse"
          [ bins.test "-e" "\${1}/ok" ]
        # write error message to stderr
        [ "exit" "0" ]
      "redirfd" "-w" "2"
      bins.echo "neither err no ok files existed, should not happen"
      "exit" "101"
    ];
  };

  # clean the environment;
  # this is the only way we can have a non-diverging
  # environment between developer machine and CI
  emptyTestEnv = test:
    writeExecline "${test.name}-empty-env" {}
      [ (runInEmptyEnv []) test ];

  testsWithEmptyEnv = pkgs.lib.mapAttrs
    (_: test: test // { test = emptyTestEnv test.test; }) tests;

  # Write a attrset which looks like
  # { "test description" = test-script-derviation }
  # to a script which can be read by `bats` (a simple testing framework).
  batsScript =
    let
      # add a few things to bats’ path that should really be patched upstream instead
      # TODO: upstream
      bats = writeExecline "bats" {} [
        (pathAdd "prepend") (pkgs.lib.makeBinPath [ pkgs.coreutils pkgs.gnugrep ])
        "${pkgs.bats}/bin/bats" "$@"
      ];
      # see https://github.com/bats-core/bats-core/blob/f3a08d5d004d34afb2df4d79f923d241b8c9c462/README.md#file-descriptor-3-read-this-if-bats-hangs
      closeFD3 = "3>&-";
    in name: tests: pkgs.lib.pipe testsWithEmptyEnv [
      (pkgs.lib.mapAttrsToList
        # a bats test looks like:
        # @test "name of test" {
        #   … test code …
        # }
        # bats is very picky about the {} block (and the newlines).
        (_: test: "@test ${pkgs.lib.escapeShellArg test.description} {\n${test.test} ${closeFD3}\n}"))
      (pkgs.lib.concatStringsSep "\n")
      (pkgs.writeText "testsuite")
      (test-suite: writeExecline name {} [
        bats test-suite
      ])
    ];

  testsuite = batsScript "run-testsuite" tests;

in {
  inherit testsuite;
  # we want the single test attributes to have their environment emptied as well.
  tests = testsWithEmptyEnv;
}
