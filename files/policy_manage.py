import requests
import yaml
import json
from argparse import ArgumentParser


ARGS = None

default_policy = {
  'default': '\n# Allow tokens to look up their own properties\npath "auth/token/lookup-self" {\n    capabilities = ["read"]\n}\n\n# Allow tokens to renew themselves\npath "auth/token/renew-self" {\n    capabilities = ["update"]\n}\n\n# Allow tokens to revoke themselves\npath "auth/token/revoke-self" {\n    capabilities = ["update"]\n}\n\n# Allow a token to look up its own capabilities on a path\npath "sys/capabilities-self" {\n    capabilities = ["update"]\n}\n\n# Allow a token to look up its own entity by id or name\npath "identity/entity/id/{{identity.entity.id}}" {\n  capabilities = ["read"]\n}\npath "identity/entity/name/{{identity.entity.name}}" {\n  capabilities = ["read"]\n}\n\n\n# Allow a token to look up its resultant ACL from all policies. This is useful\n# for UIs. It is an internal path because the format may change at any time\n# based on how the internal ACL features and capabilities change.\npath "sys/internal/ui/resultant-acl" {\n    capabilities = ["read"]\n}\n\n# Allow a token to renew a lease via lease_id in the request body; old path for\n# old clients, new path for newer\npath "sys/renew" {\n    capabilities = ["update"]\n}\npath "sys/leases/renew" {\n    capabilities = ["update"]\n}\n\n# Allow looking up lease properties. This requires knowing the lease ID ahead\n# of time and does not divulge any sensitive information.\npath "sys/leases/lookup" {\n    capabilities = ["update"]\n}\n\n# Allow a token to manage its own cubbyhole\npath "cubbyhole/*" {\n    capabilities = ["create", "read", "update", "delete", "list"]\n}\n\n# Allow a token to wrap arbitrary values in a response-wrapping token\npath "sys/wrapping/wrap" {\n    capabilities = ["update"]\n}\n\n# Allow a token to look up the creation time and TTL of a given\n# response-wrapping token\npath "sys/wrapping/lookup" {\n    capabilities = ["update"]\n}\n\n# Allow a token to unwrap a response-wrapping token. This is a convenience to\n# avoid client token swapping since this is also part of the response wrapping\n# policy.\npath "sys/wrapping/unwrap" {\n    capabilities = ["update"]\n}\n\n# Allow general purpose tools\npath "sys/tools/hash" {\n    capabilities = ["update"]\n}\npath "sys/tools/hash/*" {\n    capabilities = ["update"]\n}\n\n# Allow checking the status of a Control Group request if the user has the\n# accessor\npath "sys/control-group/request" {\n    capabilities = ["update"]\n}\n\n# Allow a token to make requests to the Authorization Endpoint for OIDC providers.\npath "identity/oidc/provider/+/authorize" {\n\tcapabilities = ["read", "update"]\n}\n', 
  'root': '',
}


def parse_arguments():
  parser = ArgumentParser()  
  parser.add_argument("--url", required=True)
  parser.add_argument("--token", required=True)
  parser.add_argument("--policies")

  global ARGS
  ARGS = vars(parser.parse_args())


def request(method: str, headers: dict = None, response_path = ".", path = None, data = None, allowed_status_codes = []) -> dict:
  url = ARGS.get("url") + path

  if headers is None:
    headers = {"X-Vault-Token": ARGS.get("token")}

  response = requests.request(method=method, url=url, headers=headers, data=data)
  if response.status_code >= 400 and response.status_code not in allowed_status_codes:
    raise ValueError("Request return status code " + str(response.status_code) + str(response.text))
  
  if response.content == b'':
    return "ok"
  
  response_content = json.loads(response.content.decode("utf-8"))
  result = response_content
  for response in response_path.split("."):
    if result.get(response) is None:
      break
    result = result.get(response)

  return result


def get_target_policies() -> dict:
  result = {}

  path = "/v1/sys/policy"
  keys_list = request(method="LIST", path=path, response_path="data.keys")
  for key in keys_list:
    key = path + "/" + key
    result[key] = request(method="GET", path=key, response_path="data.rules")
    result[key.replace("/v1/sys/policy/", "")] = result.pop(key)
  
  return result


def diff(source: dict, target: dict) -> dict:
  result = {
    "+": {},
    "-": {},
    "~": {}
  }

  for key in source:
    if key not in target:
      result["+"][key] = source[key]
    elif source[key] != target[key]:
      result["~"][key] = source[key]
  
  for key in target:
    if key not in source:
      result["-"][key] = target[key]
  
  return result


def apply(difference: dict, path_prefix: str):
  for create in difference["+"]:
    request(method="POST", path=path_prefix+create, data=difference["+"][create])

  for change in difference["~"]:
    request(method="POST", path=path_prefix+change, data=difference["~"][change])

  for delete in difference["-"]:
    request(method="DELETE", path=path_prefix+delete)


def apply_diffs():
  difference = diff(ARGS.get("policies"), get_target_policies())
  for dif in difference["+"]:
    difference["+"][dif] = {"policy": difference["+"][dif]}
  for dif in difference["~"]:
    difference["~"][dif] = {"policy": difference["~"][dif]}
  apply(difference=difference, path_prefix="/v1/sys/policy/")
  print(yaml.dump(difference))


if __name__ == "__main__":
  parse_arguments()
  ARGS["policies"] = yaml.safe_load(ARGS.get("policies"))

  if not ARGS["policies"]:
    ARGS["policies"] = dict()

  for policy in ARGS["policies"]:
    ARGS["policies"][policy] = ARGS["policies"][policy].replace("\\n", "\n")

  ARGS["policies"].update(default_policy)

  apply_diffs()
