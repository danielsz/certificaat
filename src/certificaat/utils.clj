(ns certificaat.utils
  (:require [clojure.string :as str]
            [certificaat.acme4j.certificate :as certificate]))

(defn error-msg [errors]
  (str "The following errors occurred while parsing your command:\n\n"
       (str/join \newline errors)))

(defn exit [status msg]
  (println msg)
  ;(System/exit status)
)

(defn info [{config-dir :config-dir domain :domain}]
  (let [path (str config-dir domain "/")
        cert-file (str path "domain-chain.crt")
        key-file (str path "domain.key")]
    (certificate/info cert-file key-file)))
