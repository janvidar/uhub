#!/bin/bash

docker build -t uhub:windows -f build-windows.dockerfile .
docker run --rm --name uhub-windows-build -v $(pwd)/dist:/app/dist uhub:windows
