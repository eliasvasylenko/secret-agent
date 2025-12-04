{ pkgs, ... }:
rec {
  matchString =
    value: expected:
    let
      expectedString = pkgs.writeText "expected-${value}.txt" expected;
    in
    ''
      from json import dumps, load, loads
      value = dumps(loads(${value}), sort_keys=True)
      with open("${expectedString}") as file:
        expected = dumps(load(file), sort_keys=True)
      assert value == expected, f"value '{value}' does not match expected {expected}"
    '';

  matchJson =
    value: expected: matchString value (builtins.toJSON expected);
}
