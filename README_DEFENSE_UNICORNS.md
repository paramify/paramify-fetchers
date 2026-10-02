# Paramify Defense Unicorns Usage 

## Overview
- The [./FedRAMP_20x_Class_C_UDS_Engineer_KSI_List.xlsx](./FedRAMP_20x_Class_C_UDS_Engineer_KSI_List.xlsx) is being used the state of the KSI automation and can be updated throughout this project.
- The [./manifest.yaml](./manifest.yaml) are the configuration fetchers for our environment. 
- The `[./manifest-small.yaml](./manifest-small.yaml) is an alternative faster running configuration for testing. 
- The most important fetchers we'll be creating are in [./fetchers/azure](./fetchers/azure) but others might be useful (i.e., [./fetchers/k8s](./fetchers/k8s), [./fetchers/rippling](./fetchers/rippling)).
- The most important validated we'll be creating are in [./validators/azure](./validators/azure) but other might be useful. 

## TLDR Usage

1. Follow install at `## Install` in [./README.md](./README.md) to install paramify cli and tui
2. For convinence can do `cp .env.example .env`, update variables in `.env`, and run `set -a && source .env && set +a`
3. `paramify validate manifest.yaml`
4. `paramify doctor manifest.yaml`
5. `paramify run manifest.yaml`, see results at [./evidence](./evidence)
6. `paramify upload`, see results at https://app.paramify.com/resources/evidence
7. `paramify validators check`
8. `paramify validators sync`, see validators sync'd to evidence at https://app.paramify.com/resources/evidence
9. Evidence can be associated to solutions capabilities (i.e., https://app.paramify.com/solution-capabilities/49c25501-915a-484d-bd27-3539f5ed87b3/functions?cc=baea2302-2318-526d-81bf-94689502852c&s=6ea005f0-91d5-4c11-a6f4-9fef390a40a8) by clicking the evidence tab and smashing the association button
10. Commands like `paramify programs list`, `paramify programs target ???`, `paramify manifest add-target ???`, `paramify issues upload???`, etc. might be useful at somepoint unsure how helpful right now