# COMP3703 Lab Virtual Machine Setup

The following instructions are for setting up an instance of the COMP3703 Lab Virtual Machine (VM) in a personal computer. For the VM setup for CSIT linux lab computers, see [README.md](./README.md).

The VM image can be downloaded from either one of the following links: 
- VirtualBox VM (for Intel Mac, Windows or Linux hosts). You will need to install VirtualBox software in your computer to run this VM.

    * Download link: [comp3703-2025.ova](https://anu365-my.sharepoint.com/:u:/g/personal/u4301469_anu_edu_au/Eemqj0iqT59BusM5lwM6CGIBMdzuIirJ-i5AXB5Ok6Y-hg)


-	UTM VM (for Apple Silicon). This is similar to the VirtualBox VM, but is specifically set up to run on Mac computers that use Apple Silicon (M1 or newer). You need to have the UTM app installed in your Mac to run this VM.

    - Download link: [comp3703-2025.utm.zip](https://anu365-my.sharepoint.com/:u:/g/personal/u4301469_anu_edu_au/EdCcvQeP2vJKmtEO5e0BmRcB9idC5nvwiOaa0waA6yCnZA?e=rFCHL1)

# VirtualBox VM Setup Instructions

You will need to first install the VirtualBox virtualisation software in your computer if you don't already have one installed. The lab VM has been tested using the latest VirtualBox (currently at version 7.1), and it is recommended that you use this latest version, as some configurations in the lab VM may not be backward compatible. 

1. Download and install the VirtualBox application, if you have not installed it already. It is available for free from: 

    [https://www.virtualbox.org/](https://www.virtualbox.org/)


2. Download the lab VM image for Virtualbox (comp3703-2025.ova).

3. Import the lab VM impage to Virtualbox. This can be done by  double-clicking on the VM image file (comp3703-vm.ova).

4. Select the installed VM and click `Start` on the VirtualBox to start the VM. 

You can then connect to the VM using `ssh`:

`ssh -p 5555 user1@localhost`

# UTM VM setup instructions

If you use a Mac computer with Apple silicon, you should use the UTM version of the VM; the VirtualBox VM won’t run on these CPUs.

Installation steps:

1. Download and install UTM if you don’t already have it installed.It’s freely available from https://mac.getutm.app . 
There is also a version that’s available from Apple App Store that’s
more convenient (but comes with a small fee).

2. Download the UTM VM: comp3703-2025.utm.zip. Uncompress comp3703-2025.utm.zip to obtain the folder `comp3703-2025.utm` and then simply  double-click it to launch the VM.

The instructions to connect to the UTM lab VM is the same as the VirtualBox.