import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

from src.gc import GoogleClient

def test_table():
    #Initialize the GoogleClient instance
    googleclient = GoogleClient(credentials_path='/opt/airflow/repo/secrets/cisa-cve-data-pipeline-a26a62e94ef3.json')

    #Access the BigQuery client
    bigquery_client = googleclient.bigquery_client

    try:
        dataset_id = f'{googleclient.projectID}.cve_all'
        table_id = dataset_id + '.cve_combined_final_table'

        queries_list = [

            {'query1':
                f'''
                SELECT * from `{table_id}`
                WHERE cve_id IS NULL or cve_id = '' 
                    '''},
            {'query2':
             f'''
            SELECT cve_id FROM `{table_id}`
            WHERE regexp_contains(cve_id, r"^CVE-1999-") OR REGEXP_CONTAINS(cve_id, r"^CVE-2000-")'''},
        ]

        for query in queries_list:
            querynum = list(query.keys())[0]

            query_job = bigquery_client.query(query=query.get(querynum))
            # The returned object contains errors if the job fails.
            results = query_job.result()
            result_df = results.to_dataframe()

            match querynum:
                case 'query1':
                    if not result_df.empty:
                        raise RuntimeError("DQ check FAILED: SOME CVE values are missing")
                    else:
                        logging.info("DQ check PASSED: All CVE entries have values.")

                case 'query2':
                    if result_df.empty:
                        raise RuntimeError('DQ check FAILED: There are entries missing from 1999 and 2000')
                    else:
                        logging.info('DQ check PASSED: CVE entries contain entries from 1999 and 2000 ')

    except Exception as e:
        logging.error(f"Failed to access BigQuery table: {e}")

if __name__ == "__main__":
    test_table()
