import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

from src.gc import GoogleClient as gc

def test_table():
    #Initialize the GoogleClient instance
    googleclient = gc()

    #Access the BigQuery client
    bigquery_client = googleclient.bigquery_client

    try:
        dataset_id = f'{googleclient.projectID}.cve_all'
        table_id = dataset_id + '.cve_combined_final_table'
        
        test_query = f'''
            SELECT cve_id FROM `{table_id}`
            WHERE regexp_contains(cve_id, r"^CVE-1999-") OR REGEXP_CONTAINS(cve_id, r"^CVE-2000-")
        '''

        query_job = bigquery_client.query(test_query)
        # The returned object contains errors if the job fails.
        results = query_job.result()
        result_df = results.to_dataframe()

        if result_df.empty:
            raise RuntimeError("DQ failed: no CVE IDs from 1999 or 2000 found.")
        else:
            logging.info("Data quality check PASSED: found CVE IDs from 1999 or 2000.")

    except Exception as e:
        logging.error(f"Failed to access BigQuery table: {e}")

if __name__ == "__main__":
    test_table()
