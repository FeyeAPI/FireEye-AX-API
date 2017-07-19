This is a python script that will check local directories for files.
Files found in the directory will be uploaded to a FireEye AX device for analysis.

The status of the files will be tracked in a sqllite database.

Every time the script is run it will check the configured directories for
    new files and submit any files found.

After submitting new files, the script will check the sqllite database for
    files that have already been submitted and are pending results.  If
    results are available the script will update the database appropriately
    and move the file to the corresponding results directory.

All configuration is controlled via the .feapi.ini file.

Once the .feapi.ini file contains the correct configuration information
    run the script with the -s or --setup argument to create the necessary
    directories and databases.

Once the setup is complete, run the script without any arguments to
    do the actual work.