import logging
import json 
import pandas as pd
from google.cloud import storage

from src.gc import googleClient
from src.parser import extract_cvedata

logging.basicConfig(level=logging.INFO)

def create_combined_table():
    # This function will create the combined dataset table 
    pass

def transform_tocsv_load_to_gcs_bq(year: str = ''):
    logging.info(f'Transforming raw json to csv for year: {year}')

    gc = googleClient()
    storage_client = gc.storage_client

    bucket_id = gc.bucket_name

    # fetching the bucket we need
    bucket = storage_client.bucket(bucket_id)

    # fetching raw jsons using blob names
    blob_prefix = f'{bucket_id}/{year}'
    blobs = bucket.list_blobs(prefix=blob_prefix)

    processed_records = []

    for blob in blobs:
        # we will first download the raw text
        try:
            content = blob.download_as_text()
            # Creating a valid python object from the raw json string
            cve_data_json = json.loads(content)

            #Passing this into the cve json extractor from parser.py
            record = extract_cvedata(cve_data_json= cve_data_json)

            if record:
                processed_records.append(record)

        except Exception as e:
            logging.error(f'Failed to download blob contents and create a record!: {e}') 

    # After processing each blob we have the processed_records
    logging.info(f'These are the processed records: {processed_records}')

    # Uploading processed records for the year to the gcs bucket as csv but to a new folder 
    #logging.info(f'Uploading the records for {year} to GCS ')
    #gc.csv_to_bucket(processed_records, year= year)

    # TO DO: Use the bigquery function to parse the combined csv as a new table
    



if __name__ == '__main__':
    years = ['1999']

    for year in years:
        transform_tocsv_load_to_gcs_bq(year)


            

