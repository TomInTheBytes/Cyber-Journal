# Splunk Cheatsheet

This page is a personal collection of useful Splunk queries and tips for analyzing data.

## Splunk search & field performance
In Splunk you can search for a term in the raw data or related to a specific field. While searching for a specific field (when possible) intuitively feels faster, it is not necessarily the case. 

!!! example "Summarized by ChatGPT"
    

- **Raw term search (`"search_value"`)**: Matches token anywhere in `_raw` via inverted index. Fast. May match unintended fields or text.
- **Field search (`field="search_value"`)**: Matches only parsed field values. Requires search-time extraction unless field is indexed. To check if field is indexed:
    1. `| tstats count where index=<index> by <field>` — if results, field is indexed.
    2. Field appears immediately in search app’s selected fields without extractions.
- **Performance**: Non-indexed fields are slower due to extraction overhead. Indexed fields use `tsidx` and match raw term speed or slightly faster.
- **Use field search when**: Precision is needed, avoid false positives, or downstream commands depend on that field.
- **Use raw term search when**: Maximum speed and broad matching are acceptable.
