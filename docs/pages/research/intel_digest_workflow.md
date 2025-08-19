# Automation Workflow: AI Threat Intelligence
This page showcases an automation workflow built for the tool [n8n](https://n8n.io/). 

!!! info
    The workflow has been submitted to n8n and is currently [under review](https://creators.n8n.io/workflows/7608). A JSON copy can be downloaded the repository this information is hosted on under the 'projects' folder.


## Workflow - AI Threat Intelligence: Compose Daily Digest & Viral Topics Reports

Process cybersecurity reports into an AI-generated daily threat intelligence digest and viral topic report.

![Workflow](../../media/n8n_cti_digest.png){ align=left }
/// caption
A n8n automation workflow for composing daily threat intelligence digest & viral topics reports with AI.
///

This n8n workflow simplifies the process of digesting cybersecurity reports by summarizing, deduplicating, organizing, and identifying viral topics of interest into daily emails. 

It will generate two types of emails:
- A daily digest with summaries of deduplicated cybersecurity reports organized into various topics.
- A daily viral topic report with summaries of recurring topics that have been identified over the last seven days. 


**This workflow template supports threat intelligence analysts digest the high number of cybersecurity reports they must analyse daily by decreasing the noise and tracking topics of importance with additional care, while providing customizability with regards to sources and output format.**

## How it works
The workflow follows the threat intelligence lifecycle as labelled by the coloured notes.
- Every morning, collect news articles from a set of RSS feeds.
- Merge the feeds output and prepare them for LLM consumption.
- Task an LLM with writing an intelligence briefing that summarizes, deduplicates, and organizes the topics.
- Generate and send an email with the daily digest.
- Collect the daily digests of the last seven days and prepare them for LLM consumption.
- Task an LLM with writing a report that covers 'viral' topics that have appeared prominently in the news. 
- Store this report and send out over email.

## How to use & customization
- The workflow will trigger daily at 7am. 
- The workflow can be reused for other types of news as well. The RSS feeds can be swapped out and the AI prompts can easily be altered. 
- The parameters used for the viral topic identification process can easily be changed (number of previous days considered, requirements for a topic to be 'viral').

## Requirements
- The workflow leverages Gemini (free tier) for email content generation and Baserow for storing generated reports. The viral topic identification relies on the Gemini Pro model because of a higher data quantity and more complex task.
- An SMTP email account must be provided to send the emails with. This can be through Gmail. 