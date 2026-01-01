# ** CISA CVE Vulnrichment ETL Data pipeline **

## __Overview__
This project implements a production-grade ETL (Extract, Transform, Load) pipeline using Apache Airflow to process Common Vulnerabilities and Exposures (CVE) data enriched by CISA's Authorized Data Publisher (ADP) Vulnrichment program (https://github.com/cisagov/vulnrichment/). 

The pipeline handles 120,000+ raw JSON vulnerability records, transforms them into structured formats, and stores them in a data lake for storage and data warehouse architecture.

## __Project Architecture__

### _System Components_
The pipeline operates on a GCP Compute Engine VM (e2-medium) with 2 vCPUs, 4GB RAM running Ubuntu 22.04, and consists of three primary layers:
- Orchestration Layer: Apache Airflow 2.9.3 with scheduler and webserver for workflow management
- Data Storage: PostgreSQL database for Airflow metadata
- Runtime: Python 3.11 with Docker Compose for containerization




