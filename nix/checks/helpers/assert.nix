{ pkgs, ... }:
{
  matchString =
    value: expected:
    let
      expectedString = pkgs.writeText "expected-${value}.txt" expected;
    in
    ''
      with open("${expectedString}") as file:
        from json import dumps, load, loads
        value = dumps(loads(${value}), sort_keys=True)
        expected = dumps(load(file), sort_keys=True)
        assert value == expected, f"value '{value}' does not match expected {expected}"
    '';

  matchJson =
    value: expected:
    let
      expectedString = pkgs.writeText "expected-${value}.json" (builtins.toJSON expected);
    in
    ''
      with open("${expectedString}") as file:
        from json import dumps, load, loads
        value = dumps(loads(${value}), sort_keys=True)
        expected = dumps(load(file), sort_keys=True)
        assert value == expected, f"value '{value}' does not match expected {expected}"
    '';
}
