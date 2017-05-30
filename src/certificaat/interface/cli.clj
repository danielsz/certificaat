(ns certificaat.interface.cli
  (:require [certificaat.domain :as domain]
            [certificaat.kung-fu :as k]
            [certificaat.util.configuration :as c]
            [clojure.core.async :refer [<!!]]
            [clojure.set :as set]
            [clojure.spec.alpha :as s]
            [clojure.string :as str]
            [clojure.tools.cli :refer [parse-opts]]
            [puget.printer :as puget])
  (:import clojure.lang.ExceptionInfo
           org.shredzone.acme4j.exception.AcmeServerException
           org.shredzone.acme4j.Status))

(def cli-options
  [["-d" "--config-dir CONFIG-DIR" "The configuration directory for certificaat. Default follows XDG folders convention."
    :default (c/config-dir)
    :validate [#(s/valid? ::domain/config-dir %) "Must be a string"]]
   ["-k" "--keypair-filename KEYPAIR-FILENAME" "The name of the keypair file used to register the ACME account."
    :default "account.key"
    :validate [#(s/valid? ::domain/keypair-filename %) "Must be a string"]]
   ["-t" "--key-type KEY-TYPE" "The key type, one of RSA or Elliptic Curve."
    :default :rsa
    :parse-fn keyword
    :validate [#(s/valid? ::domain/key-type %) "Must be rsa or ec"]]
   ["-s" "--key-size KEY-SIZE" "Key length used to create a RSA private key."
    :default 2048
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
    :default "acme://letsencrypt.org/staging"
    :validate [#(s/valid? ::domain/acme-uri %) "Must be a valid URI."]]
   ["-a" "--contact CONTACT" "The email address used to send you expiry notices"
    :parse-fn #(str "mailto:" %)
    :validate [#(s/valid? ::domain/contact %) "Must be a valid mailto URI."]]
   ["-o" "--organisation ORGANISATION" "The organisation you with to register with the cerfiticate"
    :validate [#(s/valid? ::domain/organisation %) "Must be a string."]]
   ["-v" nil "Verbosity level"
    :id :verbosity
    :default 0
    :assoc-fn (fn [m k _] (update-in m [k] inc))]
   ["-h" "--help"]])

(defn usage [options-summary]
  (->> ["Certificaat. General-purpose ACME client. Compatible with LetsEncrypt CA."
        ""
        "Usage: certificaat [options] action"
        ""
        "Options:"
        options-summary
        ""
        "Actions:"
        "  authorize   Authorize a domain with the ACME server. Will explain the challenge to accept."
        "  request     Will attempt to complete all challenges and request the certificate if successful."
        "  renew       Renew the certificate for an authorized domain."
        "  info        Show the expiry date of the certificate"
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
    (domain/validate ::domain/certificaat-info options)
    (catch ExceptionInfo e
      (when (not (zero? (:verbosity options)))
        (puget/cprint (s/describe ::domain/certificaat-info))
        (puget/cprint (ex-data e)))
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
      (and (= 1 (count arguments))
           (#{"authorize" "request" "renew" "info"} (first arguments))) {:action (first arguments) :options options}
      :else {:exit-message (usage summary)})))

(defn certificaat [args]
  (let [{:keys [action options exit-message ok?]} (validate-args args)]
    (if exit-message
      (exit (if ok? 0 1) exit-message)
      (case action
        "authorize" (let [options (validate ::domain/certificaat-authorize options)
                          {config-dir :config-dir domain :domain} options
                          _ (k/setup options)
                          reg (k/register options)]
                      (doseq [[name challenges] (k/authorize options reg)
                              i (range (count challenges))
                              challenge challenges
                              :let [explanation (k/explain challenge name)]]
                        (println explanation)
                        (spit (str config-dir domain "/" name "." (.getType challenge) ".challenge.txt") explanation)
                        (spit (str config-dir domain "/challenge." name "." i ".uri") (.getLocation challenge)))) 
        "request"  (let [options (validate ::domain/certificaat-request options)
                         reg (k/register options)]
                     (try
                       (doseq [c (k/challenge options)
                               :let [resp (<!! c)]]
                         (if (= Status/VALID resp)
                           (println "Well done, challenge completed.")
                           (println "Sorry, challenge failed." resp)))
                       (catch AcmeServerException e (exit 1 (.getMessage e))))
                     (k/request options reg))
        "renew" (let [options (validate ::domain/certificaat-renew options)]
                  (k/renew options))
        "info" (let [options (validate ::domain/certificaat-info options)]
                  (puget/cprint (try
                                  (k/info options)
                                  (catch java.io.FileNotFoundException e (.getMessage e)))))))))

