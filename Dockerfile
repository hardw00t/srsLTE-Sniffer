# syntax=docker/dockerfile:1.6
# Reproducible build environment for srsLTE-Sniffer v2.
#
# Two stages:
#   1. `python` — the Python analyzer/dashboard. Self-contained, no SDR.
#   2. `full`   — `python` + srsRAN_4G + the C sniffer binaries.
#
# CI builds and tests against `python`; the `full` stage is optional and
# is the one you'd run on a SDR-equipped host.

ARG PYTHON_VERSION=3.11

# ----- python stage --------------------------------------------------------

FROM python:${PYTHON_VERSION}-slim AS python

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml /app/
COPY python /app/python

RUN pip install --upgrade pip && \
    pip install -e ".[dev]"

CMD ["srslte-sniffer", "--help"]

# ----- full stage (python + srsRAN_4G) -------------------------------------

FROM ubuntu:22.04 AS full

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        git build-essential cmake pkg-config \
        libfftw3-dev libmbedtls-dev libboost-program-options-dev \
        libconfig++-dev libsctp-dev libuhd-dev uhd-host \
        python3 python3-pip python3-venv \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build srsRAN_4G. Pinned to a recent tag — bump as required.
ARG SRSRAN_TAG=23.11
RUN git clone --depth 1 --branch ${SRSRAN_TAG} \
        https://github.com/srsran/srsRAN_4G /opt/srsRAN_4G && \
    cmake -S /opt/srsRAN_4G -B /opt/srsRAN_4G/build \
          -DCMAKE_BUILD_TYPE=Release -DENABLE_GUI=OFF && \
    cmake --build /opt/srsRAN_4G/build -j"$(nproc)" && \
    cmake --install /opt/srsRAN_4G/build && \
    ldconfig

WORKDIR /app
COPY . /app

RUN pip3 install -e ".[dev]" && \
    cmake -S /app -B /app/build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /app/build -j"$(nproc)" && \
    cmake --install /app/build

CMD ["srslte-sniffer", "--help"]
