# Troubleshooting VM installation in lab computers

## `install_vm` (or `start_vm`, `stop_vm`) not found or failed to execute

Make sure that your PATH environment is updated by running:

```
export PATH=/courses/comp3703/bin:$PATH
```

If you have done this and `install_vm` is still not recognised, check that the directory `/courses/comp3703/bin` exists. If it does not, contact the local IT support as that is likely an issue with the network file server.


## Re-installing the VM

If for some reason the installation failed, make sure you remove the failed installation first before re-attempting the installation. You can try the following steps to remove a failed install. Here we assume you used the command `install_vm comp3703` to install the VM. 


- Unregister the VM using the following command:

    ```
    VBoxManage unregistervm comp3703
    ```

- Remove the VM files from "VirtualBox VMs" folder:

    ```
    rm -ri "$HOME/VirtualBox VMs/comp3703"
    ```

  You'll be prompted to remove all the files in that folder. Make sure that these are the files that you want to remove before confirming their removal.


## Port 5555 is already in use.

When starting the VM using `start_vm` command, you may encounter an error message saying that port 5555 is already in use by another program. If this happened, you would need to use a different port using the `--port` option. For example, to start the VM and forward the SSH port to 6666, run

```
start_vm comp3703 --port 6666
```

