import os
import urllib.request
import urllib.error
import gzip
import shutil


class CPEDownloader:
    """Handles downloading and uncompressing CPE dictionaries"""

    def __init__(self, url, dest_path):
        self.url = url
        self.dest_path = dest_path

    def download(self, force=False):
        """Download the file if it does not exist or force is True."""
        if not force and os.path.isfile(self.dest_path):
            print(f"Using existing file {self.dest_path} ...")
            return self.dest_path

        print(f"Downloading CPE data from {self.url} ...")
        download_path = (
            self.dest_path + ".gz" if self.url.endswith(".gz") else self.dest_path
        )

        try:
            urllib.request.urlretrieve(self.url, download_path)
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            FileNotFoundError,
            PermissionError,
        ) as e:
            print(e)
            raise

        if download_path.endswith(".gz"):
            self.uncompress(download_path)

        return self.dest_path

    def uncompress(self, gz_path):
        """Uncompress a .gz file to the destination path."""
        print(f"Uncompressing {gz_path} ...")
        try:
            with gzip.open(gz_path, "rb") as f_in:
                with open(self.dest_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(gz_path)
        except (FileNotFoundError, PermissionError) as e:
            print(e)
            raise
