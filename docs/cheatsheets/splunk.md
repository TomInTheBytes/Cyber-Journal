# Splunk Cheatsheet

This page is a personal collection of useful Splunk queries and tips for analyzing data.

## Search & field performance
In Splunk you can search for a term in the raw data or related to a specific field. While searching for a specific field (when possible) intuitively feels faster, it is not necessarily the case.     

- **Raw term search (`"search_value"`)**: Matches token anywhere in `_raw` via inverted index. Fast. May match unintended fields or text.
- **Field search (`field="search_value"`)**: Matches only parsed field values. Requires search-time extraction unless field is indexed. To check if field is indexed:
    1. `| tstats count where index=<index> by <field>` — if results, field is indexed.
    2. Field appears immediately in search app’s selected fields without extractions.
- **Performance**: Non-indexed fields are slower due to extraction overhead. Indexed fields use `tsidx` and match raw term speed or slightly faster.
- **Use field search when**: Precision is needed, avoid false positives, or downstream commands depend on that field.
- **Use raw term search when**: Maximum speed and broad matching are acceptable.

!!! example "Summarized by AI (GPT-5)"


## Querying datamodels
Datamodels can accelarate search queries in Splunk. They can also combine multiple indices. Available datamodels can be found under Settings -> Data -> Data Models. 

**1. `tstats` Command**

*   **Purpose:** Optimized for querying **accelerated data models**. Directly accesses pre-computed summaries.
*   **Syntax:** 
    ```
    | tstats <aggregation> from datamodel=<DataModelName>.<DataSetName> where <DataSetName>.<FieldName>=<Value> by <DataSetName>.<FieldName>
    ```
*   **Example:** 
    ```
    | tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic 
    where All_Traffic.dest_port=443 
    by All_Traffic.src_ip, All_Traffic.dest_ip
    ```
*   **Characteristics:**
    *   **Performance:** Superior for aggregations on large, accelerated data.
    *   **Limitations:** Restricted to fields defined in data model acceleration; limited pre-aggregation transformations.
    *   **Filtering:** Uses `where` clause.

**2. `| datamodel` Pipe Command**

*   **Purpose:** General command for retrieving events from **any data model** (accelerated or unaccelerated). Processes raw events.
*   **Syntax:** 
    ```
    | datamodel <DataModelName> <DataSetName> | search <FieldName>=<Value> | <other commands>
    ```
                    
*   **Example:** 
    ```
    | datamodel Web_Traffic HTTP_Requests
    | search status=404 AND clientip!="10.0.0.0/8"
    | eval request_size_kb = bytes / 1024
    | stats count as NotFoundCount, sum(request_size_kb) as TotalKBDelivered by url
    | sort - NotFoundCount
    | head 10
    ```
*   **Characteristics:**
    *   **Flexibility:** Allows complex initial filtering, `eval`, `rex`, and other transformations before aggregation.
    *   **Performance:** Can be slower than `tstats` for large, accelerated datasets due to raw event processing.
    *   **Filtering:** Uses standard `search` command.

**Usage:**

*   **Use `tstats`:** For rapid aggregations on large, accelerated data models with straightforward filtering.
*   **Use `| datamodel`:** For flexible event retrieval, pre-aggregation transformations, or unaccelerated data models.

!!! example "Summarized by AI (Gemini 2.5 Flash)"