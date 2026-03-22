#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import sys
from wsgiref.simple_server import make_server

import falcon
from dynaconf import Dynaconf

from cpe_guesser import CPEGuesser

# Configuration
settings = Dynaconf(settings_files=["../config/settings.yaml"])
port = settings.get("server.port", 8000)


class Search:
    def on_post(self, req, resp):
        data_post = req.bounded_stream.read()
        js = data_post.decode("utf-8")
        try:
            q = json.loads(js)
        except ValueError:
            resp.status = falcon.HTTP_400
            resp.media = "Missing query array or incorrect JSON format"
            return

        if "query" in q:
            pass
        else:
            resp.status = falcon.HTTP_400
            resp.media = "Missing query array or incorrect JSON format"
            return

        cpeGuesser = CPEGuesser()
        resp.media = cpeGuesser.guessCpe(q["query"])


class Unique:
    def on_post(self, req, resp):
        data_post = req.bounded_stream.read()
        js = data_post.decode("utf-8")
        try:
            q = json.loads(js)
        except ValueError:
            resp.status = falcon.HTTP_400
            resp.media = "Missing query array or incorrect JSON format"
            return

        if "query" in q:
            pass
        else:
            resp.status = falcon.HTTP_400
            resp.media = "Missing query array or incorrect JSON format"
            return

        cpeGuesser = CPEGuesser()
        cpes = cpeGuesser.guessCpe(q["query"])[:1][0][1]

        r = []
        if len(cpes) > 0:
            if len(cpes[0]) >= 2:
                r = cpes[0][1]

        resp.media = r


def main():
    app = falcon.App()
    app.add_route("/search", Search())
    app.add_route("/unique", Unique())

    try:
        with make_server("", port, app) as httpd:
            print(f"Serving on port {port}...")
            httpd.serve_forever()
    except OSError as e:
        print(e)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
