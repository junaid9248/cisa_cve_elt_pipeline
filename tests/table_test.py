from src.gc import GoogleClient as gc
import pytest

def test_table():
    googleclient = gc()

    storage_client = googleclient.storage_client
    bigquery_client = googleclient.bigquery_client

    try:
        dataset_id = 'cisa-cve-data-pipeline.cve_all'
        dataset = bigquery_client.get_dataset(dataset_id)
        
        test_query = (
            f'SELECT CVE_ID FROM `{dataset_id}.cve_data_combined` LIMIT 10`'
            f'WHERE CVE_ID REGEXP_CONTAINS(CVE_ID, r"^CVE-1999-") AND CVE_ID REGEXP_CONTAINS(CVE_ID, r"^CVE-2000-")'
        )

        query_job = bigquery_client.query(test_query)
        results = query_job.result()

        if results.total_rows != 0:
            return (f'Dataset {dataset_id} contains CVE IDs from 1999 or 2000, which is expected.')

    except Exception as e:
        pytest.fail(f"Failed to access BigQuery dataset: {e}")


if __name__ == "__main__":
    result = test_table()
    print(result)