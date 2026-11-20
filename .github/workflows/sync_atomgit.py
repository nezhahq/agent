import os
import time
import hashlib
import requests
from github import Github

ATOMGIT_API = "https://api.atomgit.com/api/v5"
ATOMGIT_OWNER = "naiba"
ATOMGIT_REPO = "nezha-agent"
GITHUB_REPO = "nezhahq/agent"

MAX_DOWNLOAD_ATTEMPTS = 3


# 镜像站是国内 agent 自更新的下载源：没有通过校验的文件绝不能同步过去。
# 旧实现在校验失败后递归重下，返回后外层仍会带着未校验的文件继续上传。
def download_verified_assets(release):
    for attempt in range(1, MAX_DOWNLOAD_ATTEMPTS + 1):
        files = []
        downloaded_all = True
        for asset in release.get_assets():
            name = asset.name
            response = requests.get(asset.browser_download_url)
            if response.status_code == 200:
                with open(name, "wb") as f:
                    f.write(response.content)
                print(f"Downloaded {name}")
            else:
                print(f"Failed to download {name}: HTTP {response.status_code}")
                downloaded_all = False
            files.append(get_abs_path(name))

        print("Checking file integrities")
        if downloaded_all and verify_checksum(get_abs_path("checksums.txt")):
            return files
        print(f"Download attempt {attempt} of {MAX_DOWNLOAD_ATTEMPTS} did not verify")

    raise SystemExit("Release assets failed checksum verification, nothing was synced.")


def get_github_latest_release():
    g = Github()
    repo = g.get_repo(GITHUB_REPO)
    release = repo.get_latest_release()
    if not release:
        print("No releases found.")
        return

    print(f"Latest release tag is: {release.tag_name}")
    print(f"Latest release info is: {release.body}")
    files = download_verified_assets(release)
    sync_to_atomgit(release.tag_name, release.body, files)


def sync_to_atomgit(tag, body, files):
    access_token = os.environ["ATOMGIT_PAT"]
    release_api_uri = f"{ATOMGIT_API}/repos/{ATOMGIT_OWNER}/{ATOMGIT_REPO}/releases"

    auth_headers = {"Authorization": f"Bearer {access_token}"}
    release_data = {
        "tag_name": tag,
        "name": tag,
        "body": body,
        "prerelease": False,
        "target_commitish": "main",
    }

    release_resp = None
    for attempt in range(3):
        try:
            release_resp = requests.post(
                release_api_uri, json=release_data, headers=auth_headers, timeout=30
            )
            release_resp.raise_for_status()
            break
        except requests.exceptions.Timeout:
            print(
                f"Create release timed out, retrying in 30s... (attempt {attempt + 1})"
            )
            time.sleep(30)
        except requests.exceptions.RequestException as err:
            print(f"Create release failed: {err}")
            if release_resp is not None:
                print(f"Response: {release_resp.text}")
            break

    if release_resp is None or release_resp.status_code not in (200, 201):
        print("Failed to create release on AtomGit, aborting.")
        return

    print(f"Created release {tag} on AtomGit")

    for file_path in files:
        upload_asset(access_token, tag, file_path)

    print("Sync is completed!")


def upload_asset(access_token, tag, file_path):
    file_name = os.path.basename(file_path)
    upload_url_api = (
        f"{ATOMGIT_API}/repos/{ATOMGIT_OWNER}/{ATOMGIT_REPO}"
        f"/releases/{tag}/upload_url?file_name={file_name}"
    )

    for attempt in range(3):
        try:
            resp = requests.get(
                upload_url_api,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=30,
            )
            resp.raise_for_status()
            upload_info = resp.json()

            obs_url = upload_info["url"]
            obs_headers = upload_info["headers"]

            with open(file_path, "rb") as f:
                put_resp = requests.put(
                    obs_url, headers=obs_headers, data=f, timeout=120
                )

            if put_resp.text.strip() == "success" or put_resp.status_code in (200, 201):
                print(f"Uploaded {file_name}")
                return
            else:
                print(
                    f"Upload {file_name} failed: {put_resp.status_code} {put_resp.text}"
                )
        except requests.exceptions.RequestException as err:
            print(f"Upload {file_name} attempt {attempt + 1} failed: {err}")
            time.sleep(10)

    print(f"Failed to upload {file_name} after 3 attempts")


def get_abs_path(path):
    return os.path.join(os.getcwd(), path)


def compute_sha256(file):
    sha256_hash = hashlib.sha256()
    with open(file, "rb") as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha256_hash.update(data)
    return sha256_hash.hexdigest()


def verify_checksum(checksum_file):
    if not os.path.exists(checksum_file):
        print("checksums.txt is missing")
        return False

    with open(checksum_file, "r") as f:
        lines = [line for line in f.readlines() if line.strip()]

    if not lines:
        print("checksums.txt is empty")
        return False

    for line in lines:
        checksum, file = line.strip().split()
        abs_path = get_abs_path(file)
        if not os.path.exists(abs_path):
            print(f"{file}: FAIL (not downloaded)")
            return False
        computed_hash = compute_sha256(abs_path)

        if checksum == computed_hash:
            print(f"{file}: OK")
        else:
            print(f"{file}: FAIL (expected {checksum}, got {computed_hash})")
            return False
    return True


if __name__ == "__main__":
    get_github_latest_release()
