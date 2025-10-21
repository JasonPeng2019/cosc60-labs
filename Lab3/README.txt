<sys/socket.h>, <netinet/ip.h>, and <unistd.h>—will work onLinux VM as long you have the standard development tools and headers installed. 
These are part of the GNU C Library (glibc) and are available on all mainstream Linux distributions by default or after installing the development packages.​

On Ubuntu/Debian-based systems, install them with:

sudo apt-get update && sudo apt-get install build-essential

 # Install build tools
  sudo apt-get update
  sudo apt-get install build-essential cmake pkg-config

#Make
  make deps
  make all          # Build everything
  make test         # Build and run test
  make clean        # Clean up

  Compile and run:
   gcc -std=gnu99 -Wall packets.c main.c -o packets_test
  ./packets_test

  For network operations (sending/receiving), run as root:
  sudo ./packets_test