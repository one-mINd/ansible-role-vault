import requests
import yaml
import json
from argparse import ArgumentParser


ARGS = None


def parse_arguments():
  parser = ArgumentParser()  
  parser.add_argument("--url", required=True)
  parser.add_argument("--token", required=True)
  parser.add_argument("--policies")
  parser.add_argument("--userpasses")

  global ARGS
  ARGS = vars(parser.parse_args())


def request(method: str, headers: dict = None, response_path = ".", path = None, data = None, allowed_status_codes = []) -> dict:
  url = ARGS.get("url") + path

  if headers is None:
    headers = {"X-Vault-Token": ARGS.get("token")}

  response = requests.request(method=method, url=url, headers=headers, data=data)
  if response.status_code >= 400 and response.status_code not in allowed_status_codes:
    raise ValueError("Request return status code " + str(response.status_code) + str(response.content))
  
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
      result[method] = auth_methods[method]
  
  return result


def get_target_userpasses() -> tuple:
  auth_methods = get_target_auth_methods("userpass")
  
  target = {}
  for auth_method in auth_methods:
    auth_path = "/v1/auth/" + auth_method 
    authes_list = request(method="LIST", path=auth_path+"users", response_path="data.keys", allowed_status_codes=[404])
    if authes_list == {'errors': []}:
      authes_list = []
    
    for auth in authes_list:
      # name, response = get_token_info(auth, auth_path)
      response = request(method="GET", path=auth_path+"users/"+auth, response_path="data")
      target[auth] = response
      target[auth]["auth_method"] = auth_method.replace("/", "")
    
  return target


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
    request(method="POST", path=path_prefix+difference["+"][create].pop("auth_method")+"/users/"+create, data=difference["+"][create])

  for change in difference["~"]:
    request(method="POST", path=path_prefix+difference["~"][change].pop("auth_method")+"/users/"+change, data=difference["~"][change])

  for delete in difference["-"]:
    request(method="DELETE", path=path_prefix+difference["-"][delete].pop("auth_method")+"/users/"+delete)


def apply_diffs():
  difference = diff(ARGS.get("userpasses"), get_target_userpasses())
  apply(difference=difference, path_prefix="/v1/auth/")
  print(yaml.dump(difference))


if __name__ == "__main__":
  parse_arguments()
  ARGS["userpasses"] = yaml.safe_load(ARGS.get("userpasses"))

  if not ARGS["userpasses"]:
    ARGS["userpasses"] = dict()

  apply_diffs()
