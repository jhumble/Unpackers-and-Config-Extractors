## Installation

The unpacker can be used stand-alone or in a docker container. 

### Stand-alone

```console
cd <repo_base_dir>
python3 -m pip install -r requirements.txt
python3 setup.py install
```

---

### Running within a docker container

The included Dockerfile can be used to generate a docker image.

---

#### Building the docker image

1. Build the Docker image; the following commands  will create a container with the tag named "test":
```console
cd <repo_base_dir>
docker build -t "test" .
```

2. Run the Docker image and create a local volume in `/sandbox`:
```console
docker run -v <path_containing_malware>:/sandbox -it "test"
```

---


### Running the Unpacker

```console
python3 unpack.py -vv -w /sandbox/<path_containing_malware>
```
