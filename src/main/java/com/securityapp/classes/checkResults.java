package com.securityapp.classes;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;

public class checkResults {
    private Map<String,String> missingHeaders = new HashMap<>();
    private Map<String,String> problemHeaders = new HashMap<>();
    private Map<String,String> rawHeaders = new HashMap<>();
    private int Grade = 10;

    @JsonProperty("rawHeaders")
    public Map<String, String> getRawHeaders() {
        return rawHeaders;
    }

    public void setRawHeaders(Map<String, String> rawHeaders) {
        this.rawHeaders = rawHeaders;
    }

    @JsonProperty("missingHeaders")
    public Map<String, String> getMissingHeaders() {
        return missingHeaders;
    }

    public void setMissingHeaders(Map<String, String> missingHeaders) {
        this.missingHeaders = missingHeaders;
    }

    @JsonProperty("problemHeaders")
    public Map<String, String> getProblemHeaders() {
        return problemHeaders;
    }

    public void setProblemHeaders(Map<String, String> problemHeaders) {
        this.problemHeaders = problemHeaders;
    }

    @JsonProperty("grade")
    public int getGrade() {
        return Grade;
    }

    public void setGrade(int grade) {
        Grade = grade;
    }
}
