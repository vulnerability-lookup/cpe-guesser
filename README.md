# CPE guesser

CPE Guesser is a command-line tool or web service designed to guess the CPE name based on one or more keywords. The resulting CPE can then be used with tools like [cve-search](https://github.com/cve-search/cve-search) or [vulnerability-lookup](https://github.com/cve-search/vulnerability-lookup) to perform actual searches using CPE names.

## Requirements

- [Valkey](https://valkey.io/)
- Python

## Usage

To use CPE Guesser, you need to initialize the [Valkey](https://valkey.io/) database with `import.py`.

Once initialized, you can use the software with `lookup.py` to find the most probable CPE matching the provided keywords.

Alternatively, you can call the web server (after running `server.py`). For example:

```bash
curl -s -X POST http://localhost:8000/search -d '{"query": ["tomcat"]}' | jq .
```

### Installation

1. `git clone https://github.com/cve-search/cpe-guesser.git`
2. `cd cpe-guesser`
3. Download the CPE dictionary & populate the database with `python3 ./bin/import.py` (the NVD JSON importer now uses parallel workers by default; tune with `--workers` and `--batch-size` if needed).
4. Optionally enrich the vendor/product ranking with CVE v5 data using `python3 ./bin/import_cvelistv5.py`. This downloads `./data/cvelistv5.ndjson` only when missing unless you pass `--download`. Use `--index-words` if you also want to populate `w:<word>` and `s:<word>` from CVE v5 data, and review `set:missing_words_from_cvelistv5` for words that were not already indexed in Valkey.
5. Take a cup of black or green tea ().
6. `python3 ./bin/server.py` to run the local HTTP server.

If you don't want to install it locally, there is a public online version. Check below.

### Docker

#### Single image with existing Valkey 

```bash
docker build . -t cpe-guesser:l.0
# Edit settings.yaml content and/or path
docker run cpe-guesser:l.0 -v $(pwd)/config/settings.yaml:/app/config/settings.yaml
# Please wait for full import
```

#### Docker-compose

```bash
cd docker
# Edit docker/settings.yaml as you want
docker-compose up --build -d
# Please wait for full import
```

#### Specific usage

If you do not want to use the Web server, `lookup.py` can still be used. Example: `docker exec -it cpe-guesser python3 /app/bin/lookup.py tomcat`

## Public online version

[cpe-guesser.cve-search.org](https://cpe-guesser.cve-search.org) is public online version of CPE guesser which can be used via
a simple API. The endpoint is `/search` and the JSON is composed of a query list with the list of keyword(s) to search for.

```bash
curl -s -X POST https://cpe-guesser.cve-search.org/search -d "{\"query\": [\"outlook\", \"connector\"]}" | jq .
```

```json
[
  [
    18117,
    "cpe:2.3:a:microsoft:outlook_connector"
  ],
  [
    60947,
    "cpe:2.3:a:oracle:oracle_communications_unified_communications_suite_connector_for_microsoft_outlook"
  ],
  [
    68306,
    "cpe:2.3:a:oracle:corporate_time_outlook_connector"
  ]
]
```

The endpoint `/unique` is available to retrieve only the best-matching CPE entry.

```bash
curl -s -X POST https://cpe-guesser.cve-search.org/unique -d "{\"query\": [\"outlook\", \"connector\"]}" | jq .
```

```json
"cpe:2.3:a:oracle:corporate_time_outlook_connector"
```

### Command line - `lookup.py`

```text
usage: lookup.py [-h] [--unique] WORD [WORD ...]

Find potential CPE names from a list of keyword(s) and return a JSON of the results

positional arguments:
  WORD        One or more keyword(s) to lookup

options:
  -h, --help  show this help message and exit
  --unique    Return the best CPE matching the keywords given
```

```bash
python3 lookup.py microsoft sql server | jq .
```

```json
[
  [
    51325,
    "cpe:2.3:a:microsoft:sql_server_2017_reporting_services"
  ],
  [
    51326,
    "cpe:2.3:a:microsoft:sql_server_2019_reporting_services"
  ],
  [
    57898,
    "cpe:2.3:a:quest:intrust_knowledge_pack_for_microsoft_sql_server"
  ],
  [
    60386,
    "cpe:2.3:o:microsoft:sql_server"
  ],
  [
    60961,
    "cpe:2.3:a:microsoft:sql_server_desktop_engine"
  ],
  [
    64810,
    "cpe:2.3:a:microsoft:sql_server_reporting_services"
  ],
  [
    75858,
    "cpe:2.3:a:microsoft:sql_server_management_studio"
  ],
  [
    77570,
    "cpe:2.3:a:microsoft:sql_server"
  ],
  [
    78206,
    "cpe:2.3:a:ibm:tivoli_storage_manager_for_databases_data_protection_for_microsoft_sql_server"
  ]
]
```

## How does this work?

A CPE entry is composed of a human readable name with some references and the structured CPE name.

NVD CPE Dictionary 2.0 JSON feeds:

```json
    {
      "cpe": {
        "deprecated": false,
        "cpeName": "cpe:2.3:a:10web:form_maker:1.7.17:*:*:*:*:wordpress:*:*",
        "cpeNameId": "A6F0EC33-CD55-4FE2-8B55-5C0F9CC88BF9",
        "lastModified": "2019-06-04T16:47:17.300",
        "created": "2019-06-04T16:47:17.300",
        "titles": [
          {
            "title": "10web Form Maker 1.7.17 for WordPress",
            "lang": "en"
          }
        ],
        "refs": [
          {
            "ref": "https://wordpress.org/plugins/form-maker/#developers",
            "type": "Change Log"
          }
        ]
      }
    },
```

Legacy XML feeds:

```xml
  <cpe-item name="cpe:/a:10web:form_maker:1.7.17::~~~wordpress~~">
    <title xml:lang="en-US">10web Form Maker 1.7.17 for WordPress</title>
    <references>
      <reference href="https://wordpress.org/plugins/form-maker/#developers">Change Log</reference>
    </references>
    <cpe-23:cpe23-item name="cpe:2.3:a:10web:form_maker:1.7.17:*:*:*:*:wordpress:*:*"/>
  </cpe-item>
```

The CPE name is structured with a vendor name, a product name and some additional information.
CPE name can be easily changed due to vendor name or product name changes, some vendor/product are
sharing common names or name is composed of multiple words.

### Data

Split vendor name and product name (such as `_`) into single word(s) and then canonize the word. Building an inverse index using
the cpe vendor:product format as value and the canonized word as key.  Then cpe guesser creates a ranked set with the most common
cpe (vendor:product) per version to give a probability of the CPE appearance.

You can also build the ranking directly from the CVE v5 NDJSON dump. The importer scans the full record recursively so it can pick up
CPE values from both affected-product metadata and vulnerable configuration blocks, then increments the `rank:cpe` and
`rank:vendor_product` sorted sets using the normalized `cpe:2.3:<part>:<vendor>:<product>` tuple. It also records any vendor/product words whose `w:<word>` set does not already exist into `set:missing_words_from_cvelistv5`, and `--index-words` lets the CVE v5 importer populate `w:<word>` and `s:<word>` just like the NVD importer.

### Valkey structure

- `w:<word>` set
- `s:<word>` sorted set with a score depending of the number of appearance
- `rank:cpe` sorted set of common `vendor:product` tuples
- `rank:vendor_product` alias sorted set of the same tuple ranking, populated by both importers
- `set:missing_words_from_cvelistv5` set of vendor/product words seen in CVE v5 CPEs that were not already present as `w:<word>` keys before the record was processed

## License

Software is open source and released under a 2-Clause BSD License

~~~
  Copyright (C) 2021-2025 Alexandre Dulaunoy
  Copyright (C) 2021-2025 Esa Jokinen
~~~

We welcome contributions! All contributors collectively own the CPE Guesser project. By contributing, contributors also acknowledge the [Developer Certificate of Origin](https://developercertificate.org/) when submitting pull requests or using other methods of contribution.
