# Model Armor Workflow Script

This directory contains an interactive Python script demonstrating the full lifecycle of a Google Cloud Model Armor template using the Python SDK.

## Purpose

The [model_armor_workflow.py](model_armor_workflow.py) script allows you to:
1.  **Interactively configure** a Model Armor security template with various filters.
2.  **Create** the template in a specified Google Cloud location.
3.  **Verify** creation by listing available templates.
4.  **Test** the template against a set of predefined sample prompts representing different threat categories.

## Features

The script prompts you to configure the following capabilities:
*   **Malicious URL Detection**: Identifies harmful web addresses.
*   **Prompt Injection & Jailbreak Detection**: Catches attempts to bypass safety controls. You can set confidence levels (Low, Medium, High).
*   **Sensitive Data Protection (SDP)**: Detects PII (like credit cards) to prevent data leakage.
*   **Responsible AI (RAI)**: Filters for Hate Speech, Harassment, Dangerous Content, and Sexually Explicit content.
*   **Additional Configurations**: Supports multi-language detection and logging options.

## Setup and Usage

### 1. Create and Activate Virtual Environment

Create a virtual environment to manage dependencies:

```console
python3 -m venv .venv
```

Activate the virtual environment:

*   **Linux/macOS**:
    ```console
    source .venv/bin/activate
    ```
*   **Windows**:
    ```console
    .venv\Scripts\activate
    ```

### 2. Install Dependencies

Install the required packages:

```console
pip install -r requirements.txt
```

### 3. Authentication

Ensure you have Application Default Credentials configured:

```console
gcloud auth application-default login
```

### 4. Run the Script

Run the interactive script:

```console
python model_armor_workflow.py
```

Follow the interactive prompts to configure your template and enter your GCP Project ID.

> [!IMPORTANT]
> If you are integrating with **Gemini Enterprise**, ensure the region you select matches your Gemini Enterprise instance region exactly. Note that `global` templates may not be supported for creation in all project environments.

## Sample Tests Included

After creating the template, the script automatically runs tests for:
*   Safe Prompts
*   Prompt Injection (Blatant and Indirect)
*   Borderline Hate Speech
*   PII (Credit Card numbers)
*   Malicious URLs (using the Google Safe Browsing test URL)
