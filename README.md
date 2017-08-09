# Griffin Trace Annotator

Python script used to provide offline annotation to Griffin traces.

## Usage

Pull the repository, and run the script as follows:

```python annotate_griffin_trace.py [parsed_pt_log_file] [readelf_output]```

To generate the PT log file from Griffin, refer to the Griffin Trace repository (https://github.com/TJAndHisStudents/Griffin-Trace).

To generate the readelf output, analyze the binary with readelf using the --wide and -s flags:

```readelf --wide -s [binary]```

The output from the annotator prints directly to the console, so you can feed the output to a new file:

```python annotate_griffin_trace.py [parsed_pt_log_file] [readelf_output] > [annotated_pt_log_file]```
