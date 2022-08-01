import requests
import yaml
import json
from argparse import ArgumentParser


ARGS = None

default_auth_methods = {
  "token": {
    'config': {
      'default_lease_ttl': 0, 
      'force_no_cache': False, 
      'max_lease_ttl': 0, 
      'token_type': 'default-service'
    }, 
    'description': 'token based credentials', 
    'local': False, 
    'options': None, 
    'seal_wrap': False, 
    'type': 'token'
  }
}


def parse_arguments():
  parser = ArgumentParser()  
  parser.add_argument("--url", required=True)
  parser.add_argument("--token", required=True)
  parser.add_argument("--auth_methods")

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


def get_target_auth_methods(auth_method=None) -> dict:
  path = "/v1/sys/auth"
  auth_methods = request(method="GET", path=path, response_path="data")
  result = {}
  for method in auth_methods:
    if auth_method is None or auth_methods[method].get('type') == auth_method:
      auth_methods[method].pop('uuid')
      auth_methods[method].pop('accessor')
      auth_methods[method].pop('external_entropy_access')
      result[method.replace("/", "")] = auth_methods[method]
  
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
    else: 
      for field in source[key]:
        if field in target[key] and source[key][field] != target[key][field]:
          result["~"][key] = source[key]
          break
  
  for key in target:
    if key not in source:
      result["-"][key] = target[key]
  
  return result


def apply(difference: dict, path_prefix: str):
  for create in difference["+"]:
    request(method="POST", path=path_prefix+create, data=difference["+"][create])

  for change in difference["~"]:
    request(method="POST", path=path_prefix+change+"/tune", data=difference["~"][change])

  for delete in difference["-"]:
    request(method="DELETE", path=path_prefix+delete)


def apply_diffs():
  difference = diff(ARGS.get("auth_methods"), get_target_auth_methods())
  apply(difference=difference, path_prefix="/v1/sys/auth/")
  print(yaml.dump(difference))


if __name__ == "__main__":
  parse_arguments()
  ARGS["auth_methods"] = yaml.safe_load(ARGS.get("auth_methods"))

  if not ARGS["auth_methods"]:
    ARGS["auth_methods"] = dict()

  ARGS["auth_methods"].update(default_auth_methods)
  
  apply_diffs()
