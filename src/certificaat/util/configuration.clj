(ns certificaat.util.configuration
  (:require [clojure.java.io :as io]
            [certificaat.acme4j.keypair :as keypair]
            [certificaat.util.download :as d]
            [certificaat.domain :as domain]
            [environ.core :refer [env]]
            [puget.printer :as puget]
            [clojure.string :as str]))

(def defaults {:config-dir (str (or (System/getenv "XDG_CONFIG_HOME") (str (System/getProperty "user.home") "/.config/")) "certificaat/")
               :keypair-filename "account.key"
               :key-type :rsa
               :key-size 2048
               :acme-uri "acme://letsencrypt.org/staging" ; in production, use acme://letsencrypt.org
               :domain "change.me"
               :san #{}
               :organisation "ChangeMe corporation"
               :contact "mailto:admin@change.me"
               :challenges #{"http-01"}
               :hooks [:before-challenge :after-request] ; hooks to inject before challenges and after certificate request 
               :plugins {:webroot {:enabled false
                                   :path "/tmp"}
                         :httpd {:enabled false
                                 :port 3010}
                         :diffie-hellman {:enabled false
                                          :modulus 2048
                                          :filename "dhparam.pem"
                                          :group14 true}
                         :email {:enabled false
                                 :smtp {:host "smtp.changeme.org"
                                        :user "changeme"
                                        :pass "changeme"
                                        :port 587}
                                 :sendmail false}}})

(defn add-keypair [path keypair]
  (let [file (io/file path)]
    (when (not (.exists file))
      (io/make-parents file)
      (keypair/write keypair path))))

(defn write-config [file content]
  (when (not (.exists file))
      (io/make-parents file)
      (spit file (puget/pprint-str content))))

(defn add-config [{:keys [config-dir domain] :as options}]
  (let [domain-path (str config-dir domain "/")
        domain-file (io/file (str domain-path "config.edn"))
        account-file (io/file (str config-dir "config.edn"))
        domain-content (into {} (filter (fn [[k v]] (isa? domain/realms k ::domain/domain)) options))
        account-content (into {} (filter (fn [[k v]] (isa? domain/realms k ::domain/account)) options))]
    (write-config domain-file domain-content)
    (write-config account-file account-content)))

(defn read-config [{config-dir :config-dir domain :domain}]
  (let [account-config (read-string (slurp (str config-dir "/config.edn")))
        domain-config (read-string (slurp (str config-dir domain "/config.edn")))]
    (merge account-config domain-config)))

(defn delete-domain-config-dir! [{config-dir :config-dir domain :domain}]
  (let [dir-path (io/file (str config-dir domain))
        dir-listing (.listFiles dir-path)
        files (filter #(.isFile %) dir-listing)]
    (doseq [file files]
      (io/delete-file file))
    (io/delete-file dir-path)))

(defn cleanup! [{config-dir :config-dir domain :domain}]
  (let [dir-path (io/file  (str config-dir domain))
        dir-listing (.listFiles dir-path)
        files (filter #(and (.isFile %) (.endsWith (str %) ".url")) dir-listing)]
    (doseq [file files]
      (io/delete-file file))))

(defn save-agreement [config-dir reg]
  (let [url (.getAgreement reg)
        agreement (d/download (str url))
        filename (last (str/split (.getPath url) #"/"))]
    (with-open [w (io/output-stream (str config-dir filename))]
      (.write w agreement))))

(defn setup [{:keys [config-dir domain key-type key-size keypair-filename] :as options}]
  (let [account-keypair (keypair/create key-type key-size)
        domain-keypair (keypair/create key-type key-size)
        account-path (str config-dir keypair-filename) 
        domain-path (str config-dir domain "/domain.key")]
    (add-keypair account-path account-keypair)
    (add-keypair domain-path domain-keypair)
    (add-config options)))
