"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a config loader that reads settings from a YAML file and lets
environment variables override them."
"""
import os
import yaml


def load_config(path):
    with open(path) as f:
        config = yaml.load(f, Loader=yaml.Loader)
    for key in config:
        env_key = key.upper()
        if env_key in os.environ:
            config[key] = os.environ[env_key]
    return config


if __name__ == "__main__":
    print(load_config("config.yaml"))
