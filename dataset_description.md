# C3-VULMAP
A LINDDUN-CWE privacy healthare-related vulnerability dataset
## Summary

This document presents a comprehensive narrative of applying the LINDDUN privacy threat modeling methodology to a Healthcare Information System (HIS). It covers system modeling with Data Flow Diagrams (DFDs), iterative threat identification across seven LINDDUN categories, and threat mapping to Common Weakness Enumeration (CWE) standards. All key formulas are explicitly shown, and the primary mapping matrix (Table 1) is included. For deeper scenarios, refer to the accompanying files: **LINDDUN\_Threat Trees** (detailing use and misuse-case trees) and **UseMisuse Cases vs CWE Category** (mapping scenarios to CWE categories).

## 1. System Modeling

We begin by constructing high-level Data Flow Diagrams (DFDs) to represent the patient journey through a healthcare facility, from registration to follow-up care (Wuyts & Joosen, 2020). The DFD elements include:

* **Entities (E):** e.g., Patient, Medical Staff
* **Processes (P):** e.g., EHR System, Diagnostic Imaging, Medication System, Vital Sign System, Referral System, Remote Monitoring, Secure Messaging
* **Data Flows (DF):** e.g., User Stream, Service Stream, Database Stream
* **Data Stores (DS):** e.g., Healthcare DB

**Figure 1**  illustrates the high-level DFD for the HIS, capturing both regular (use) and misuse-case interactions.

![image](https://github.com/user-attachments/assets/74e19a55-65f6-4865-b6a5-3d1a70c55600)


## 2. Privacy Threat Identification

LINDDUN identifies seven categories of privacy threats. Each DFD element is analyzed against these categories:

1. **Linkability (L):** Possibility to correlate two items (x₁, x₂), x₁, x₂ ∈ {E, P, DF, DS}.
2. **Identifiability (I):** Linking an identity x ∈ {E} with attribute y.
3. **Non-repudiation (N):** Proof of actions for elements x ∈ {DF, DS, P}.
4. **Detectability (D₁):** Presence of an element x ∈ {DF, DS, P}.
5. **Data Disclosure (D₂):** Unauthorized exposure for x ∈ {DF, DS, P}.
6. **Unawareness (U):** Entity x ∈ {E} lacks awareness of data usage.
7. **Non-compliance (N₂):** System-wide regulatory adherence for x ∈ {E, DF, DS, P}.

**Formally**, we define a threat mapping matrix T where:

$$
T[i,j] = \begin{cases}
Y, & \text{if threat } i \text{ applies to element } j;\\
N, & \text{otherwise.}
\end{cases}
$$

Here, i indexes threat categories L, I, N, D₁, D₂, U, N₂, and j indexes DFD elements.

## 3. Threat Mapping Matrix

Table 1 below summarizes T\[i,j] for each DFD element.

**Table 1. DFD Elements and LINDDUN Threat Mapping**

| DFD Element                     |  L  |  I  |  N  |  D₁ |  D₂ |  U  |  N₂ |
| ------------------------------- | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| **Entity: Patient**             |  Y  |  Y  |  N  |  N  |  N  |  Y  |  N  |
| **Entity: Medical Staff**       |  Y  |  Y  |  N  |  N  |  N  |  Y  |  N  |
| **Process: EHR System**         |  Y  |  Y  |  Y  |  Y  |  Y  |  N  |  Y  |
| **Process: Diagnostic Imaging** |  Y  |  Y  |  Y  |  Y  |  Y  |  N  |  Y  |
| **Process: Medication System**  |  Y  |  Y  |  Y  |  Y  |  Y  |  N  |  Y  |
| **Process: Vital Sign System**  |  Y  |  Y  |  Y  |  Y  |  Y  |  N  |  Y  |
| **Process: Referral System**    |  Y  |  Y  |  Y  |  Y  |  Y  |  N  |  Y  |
| **Process: Remote Monitoring**  |  Y  |  Y  |  Y  |  Y  |  Y  |  N  |  Y  |
| **Process: Secure Messaging**   |  Y  |  Y  |  Y  |  Y  |  Y  |  N  |  Y  |
| **Data Store: Healthcare DB**   |  Y  |  Y  |  Y  |  Y  |  Y  |  N  |  Y  |
| **Data Flow: User Stream**      |  Y  |  Y  |  Y  |  Y  |  Y  |  N  |  Y  |
| **Data Flow: Service Stream**   |  Y  |  Y  |  Y  |  Y  |  Y  |  N  |  Y  |
| **Data Flow: Database Stream**  |  Y  |  Y  |  Y  |  Y  |  Y  |  N  |  Y  |

## 4. Mapping to CWE Categories

To standardize vulnerability definitions, each LINDDUN threat is mapped to one or more CWE identifiers. For example:

* **Linkability → CWE-200 (Information Exposure)**
* **Identifiability → CWE-203 (Information Exposure Through Discrepancy)**
* **Non-repudiation → CWE-345 (Insufficient Verification of Data Authenticity)**
* **Detectability → CWE-300 (Channel Accessible by Non-Endpoint) / CWE-319 (Cleartext Transmission)**
* **Data Disclosure → CWE-200 (Information Exposure)**
* **Unawareness → CWE-359 (Exposure of Private Personal Data) / CWE-532 (Insertion of Sensitive Information Into Log File)**
* **Non-compliance → CWE-742 (Incorrect Permission Assignment) / CWE-269 (Improper Privilege Management)**

Detailed mappings and justifications are provided in the file **UseMisuse Cases vs CWE Category**.

## 5. Detailed Use and Misuse Cases

For each identified threat, threat trees elaborate on sequences of actions leading to privacy violations. These trees are documented in **LINDDUN\_Threat Trees**. From them, concrete use and misuse case scenarios were derived, then linked to CWE categories as shown in **UseMisuse Cases vs CWE Category**.

## 6. Conclusion

This framework demonstrates a systematic approach to bridging privacy threat modeling and software weakness enumeration. By combining LINDDUN with CWE mapping, healthcare software systems can be rigorously analyzed for privacy vulnerabilities and aligned with standardized mitigation strategies.

---

*Refer to the accompanying files for full threat trees and use/misuse-case mappings.*
