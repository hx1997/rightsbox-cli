//
// Created by hx1997 on 2017/11/12.
//

#ifndef RIGHTSBOX_CPP_BOXRUN_H
#define RIGHTSBOX_CPP_BOXRUN_H

#include <windows.h>
#include "utils/TokenUtils.h"

class Sandbox {

private:

    // Each Sandbox is assigned one Job
    class Job {
        Sandbox& sandbox;

    public:
        // When constructing a Job, pass the parent Sandbox instance
        // to allow access to hJob field by member methods of Job class
        explicit Job(Sandbox& box) : sandbox(box) { }

        // Create a job object, assign a process to it and set limits on the job.
        // hProcess is the handle to the process
        DWORD ConfineProcessToJob(HANDLE hProcess);

        // Set UI limits on the job.
        int SetJobLimits(DWORD dwUILimits);

        // Create a completion port and assoc the job with it
        // To receive notifs about job events, e.g. new process created
        DWORD RegisterJobNotify();

        // Terminate all processes in the job object and close the handle
        DWORD StopJob();

    protected:
        // Handle to the job object associated with the sandbox
        HANDLE hJob = nullptr;

        // Handle to the completion port associated with the job object
        HANDLE hIocp = nullptr;
    };

    Job* job;

public:

    // Instantiate and assign the Job on construction
    Sandbox() : job(new Job(*this)) {};

    // Free the Job on destruction
    ~Sandbox() { delete job; };

    // Start a process, specified by szPath, in the sandbox
    // bDropRights determines whether sandboxed processes are stripped of administrative rights
    DWORD RunSandboxed(LPCWSTR szPath, BOOL bDropRights);

    // Stop the sandbox and terminate all processes in it
    DWORD StopSandbox();



};

#endif //RIGHTSBOX_CPP_BOXRUN_H