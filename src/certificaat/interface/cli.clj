(ns certificaat.interface.cli
  (:require [certificaat.domain :as domain]
            [certificaat.kung-fu :as k]
            [certificaat.hooks :as h]
            [certificaat.plugins.webroot :as w]
            [certificaat.util.configuration :as c]
            [certificaat.util.tentoonstelling :as t]
            [clojure.core.async :refer [<!!]]
            [clojure.set :as set]
            [clojure.spec.alpha :as s]
            [clojure.string :as str]
            [clojure.tools.cli :refer [parse-opts get-default-options]]
            [puget.printer :as puget]
            [clojure.java.io :as io])
  (:import clojure.lang.ExceptionInfo
           (org.shredzone.acme4j.exception AcmeServerException AcmeUnauthorizedException)
           org.shredzone.acme4j.Status))

(def cli-options
  [["-d" "--config-dir CONFIG-DIR" "The configuration directory for certificaat. Default follows XDG folders convention."
    :default (:config-dir c/defaults)
    :validate [#(s/valid? ::domain/config-dir %) "Must be a string"]]
   ["-k" "--keypair-filename KEYPAIR-FILENAME" "The name of the keypair file used to register the ACME account."
    :default (:keypair-filename c/defaults)
    :validate [#(s/valid? ::domain/keypair-filename %) "Must be a string"]]
   ["-t" "--key-type KEY-TYPE" "The key type, one of RSA or Elliptic Curve."
    :default (:key-type c/defaults)
    :parse-fn keyword
    :validate [#(s/valid? ::domain/key-type %) "Must be rsa or ec"]]
   ["-s" "--key-size KEY-SIZE" "Key length used to create a RSA private key."
    :default (:key-size c/defaults)
    :parse-fn #(Integer/parseInt %)
    :validate [#(s/valid? ::domain/key-size %) "Must be 1024, 2048 or 4096"]]
   ["-m" "--domain DOMAIN" "The domain you wish to authorize"
    :validate [#(s/valid? ::domain/domain %) "Must be a valid domain"]]
   ["-n" "--san SAN" "Subject Alternative Name. Additional domain to be authorized. You can repeat this option."
    :parse-fn #(set [%])
    :assoc-fn (fn [m k v] (update-in m [k] #(into #{} (set/union % v))))
    :validate [#(s/valid? ::domain/san %) "Must be a valid domain"]]
   ["-c" "--challenges CHALLENGES" "A challenge you can complete. You can repeat this option."
    :parse-fn #(set [%])
    :assoc-fn (fn [m k v] (update-in m [k] #(into #{} (set/union % v))))
    :validate [#(s/valid? ::domain/challenges %) "Must be one of dns-01 or http-01"]]
   ["-u" "--acme-uri ACME-URI" "The URI of the ACME server’s directory service as documented by the CA."
    :validate [#(s/valid? ::domain/acme-uri %) "Must be a valid URI."]]
   ["-a" "--contact CONTACT" "The email address used to send you expiry notices"
    :parse-fn #(str "mailto:" %)
    :validate [#(s/valid? ::domain/contact %) "Must be a valid mailto URI."]]
   ["-o" "--organisation ORGANISATION" "The organisation you with to register with the cerfiticate"
    :validate [#(s/valid? ::domain/organisation %) "Must be a string."]]
   ["-w" "--webroot WEBROOT" "Web server directory where the ACME challenge files reside"
    :validate [#(s/valid? ::domain/webroot %) "Must be a valid directory in the file system"]]
   ["-v" nil "Verbosity level"
    :id :verbosity
    :default 0
    :assoc-fn (fn [m k _] (update-in m [k] inc))]
   ["-h" "--help"]])

(defn usage [options-summary]
  (->> [""
        "Certificaat. General-purpose ACME client. Compatible with LetsEncrypt CA."
        ""
        "Usage: certificaat [options] action"
        ""
        "Actions:"
        "  authorize   Authorize a domain with the ACME server. Will explain the challenge to accept."
        "  request     Will attempt to complete all challenges and request the certificate if successful."
        "  renew       Renew the certificate for an authorized domain."
        "  info        Show the expiry date of the certificate"
        ""
        "Options:"
        options-summary
        ""
        "Please refer to the README on github for more information. https://github.com/danielsz/certificaat"
        ""
        ""]
       (str/join \newline)))


(defn error-msg [errors]
  (str "The following errors occurred while parsing your command:\n\n"
       (str/join \newline errors)))

(defn exit [status msg]
  (println msg)
  (System/exit status))

(defn validate [spec options]
  (try
    (domain/validate spec options)
    (catch ExceptionInfo e
      (when-let [verbosity (:verbosity options)]
        (when (not (zero? verbosity))
          (puget/cprint (s/describe spec))))
      (puget/cprint (ex-data e))
      (exit 1 (.getMessage e)))))

(defn validate-args
  "Validate command line arguments. Either return a map indicating the program
  should exit (with a error message, and optional ok status), or a map
  indicating the action the program should take and the options provided."
  [args]
  (let [{:keys [options arguments errors summary]} (parse-opts args cli-options)]
    (cond
      (:help options) {:exit-message (usage summary) :ok? true}
      errors {:exit-message (error-msg errors)}
      (> (count arguments) 1) {:exit-message "Too many actions provided. See --help for usage instructions."}
      (s/valid? ::domain/cli-actions (first arguments)) {:action (first arguments) :options options}
      :else {:exit-message (usage summary)})))

(defn register [options] (k/register options))
(defn authorize [{config-dir :config-dir domain :domain :as options}]
  (let [reg (k/register options)]
    (doseq [[name challenges] (k/authorize options reg)
            i (range (count challenges))
            challenge challenges
            :let [explanation (k/explain challenge name)]]
      (println explanation)
      (spit (str config-dir domain "/" name "." (.getType challenge) ".challenge.txt") explanation)
      (spit (str config-dir domain "/challenge." name "." i ".uri") (.getLocation challenge)))))
(defn accept-challenges [options]
  (try
      (doseq [c (k/challenge options)
              :let [resp (<!! c)]]
        (if (= Status/VALID resp)
          (println "Well done, challenge completed.")
          (println "Sorry, challenge failed." resp)))
      (catch AcmeServerException e (exit 1 (.getMessage e)))))
(defn request [options]
  (let [reg (k/register options)]
    (try 
      (k/request options reg) ; will throw AcmeUnauthorizedException if the authorizations of some or all involved domains have expired  
      (catch AcmeUnauthorizedException e (exit 1 (.getMessage e)))) ))

(defn run [{config-dir :config-dir domain :domain :as options}]
  (let [config-dir-listing (.listFiles (io/file (str config-dir)))
        domain-dir-listing (.listFiles (io/file (str config-dir domain)))
        listing (concat config-dir-listing domain-dir-listing)
        files (filter #(.isFile %) listing)]
    (condp not-any? files
      #(= "registration.uri" (.getName %)) (register options)
      #(re-find (re-pattern (str "challenge." domain "." "\\d+" ".uri")) (.getName %)) (do (authorize options)
                                                                                           (h/run-hooks :before-challenge options))
      #(= "certificate.uri" (.getName %)) (do (accept-challenges options)
                                              (request options)
                                              (h/run-hooks :after-request options))
      (exit 0 "Nothing left to do at this point in time."))))

(defn certificaat [args]
  (let [{:keys [action options exit-message ok?]} (validate-args args)]
    (if exit-message
      (exit (if ok? 0 1) exit-message)
      (case action
        "init"      (let [cli-options (validate ::domain/cli-options options)
                          config-options (validate ::domain/config c/defaults)
                          options (merge config-options cli-options)]
                      (k/setup options))
        "run"       (let [cli-options (validate ::domain/cli-options options)
                          config-options (validate ::domain/config (c/read-config cli-options))
                          options (merge config-options cli-options)]
                      (loop []
                        (run options)
                        (recur))) 
        "reset"     (let [options (validate ::domain/cli-options options)]
                      (try (t/confirm-dialog "Are you sure?" (str "This will delete everything under " (:config-dir options) (:domain options)))
                           (c/delete-domain-config-dir! options)
                           (catch Exception e (println (.getMessage e)))))
        "info" (let [cli-options (validate ::domain/cli-options options)
                     config-options (validate ::domain/config (c/read-config options))]
                  (puget/cprint (try
                                  (k/info cli-options)
                                  (catch java.io.FileNotFoundException e (.getMessage e))))
                  (when (not (zero? (:verbosity options)))
                    (puget/cprint config-options)))
        "cron" (let [cli-options (validate ::domain/cli-options options)
                     config-options (validate ::domain/config (c/read-config options))
                     options (merge config-options cli-options)]
                 (do (request options)
                     (h/run-hooks :after-request options)))))))

