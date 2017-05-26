(ns certificaat.interface.cli
  (:require
            [clojure.tools.cli :refer [parse-opts]]
            [certificaat.domain :as domain :refer [validate]]
            [clojure.spec.alpha :as s]
            [clojure.string :as str]
            [clojure.set :as set]))

(def cli-options
  [["-d" "--config-dir CONFIG-DIR" "The configuration directory for certificaat. Default follows XDG folders convention."
    :default (str (System/getProperty "user.home") "/.config/certificaat/")
    :validate [#(s/valid? ::domain/config-dir %) "Must be a string"]]
   ["-k" "--keypair-filename KEYPAIR-FILENAME" "The name of the keypair file used to register the ACME account."
    :default "acme-account-keypair.pem"
    :validate [#(s/valid? ::domain/keypair-filename %) "Must be a string"]]
   ["-t" "--key-type KEY-TYPE" "The key type, one of RSA or Elliptic Curve."
    :parse-fn keyword
    :validate [#(s/valid? ::domain/key-type %) "Must be rsa or ec"]]
   ["-s" "--key-size KEY-SIZE" "Key length used to create a RSA private key."
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
   ["-h" "--help"]])

(defn usage [options-summary]
  (->> ["This is my program. There are many like it, but this one is mine."
        ""
        "Usage: program-name [options] action"
        ""
        "Options:"
        options-summary
        ""
        "Actions:"
        "  start    Start a new server"
        "  stop     Stop an existing server"
        "  status   Print a server's status"
        ""
        "Please refer to the manual page for more information."]
       (str/join \newline)))


(defn error-msg [errors]
  (str "The following errors occurred while parsing your command:\n\n"
       (str/join \newline errors)))

(defn exit [status msg]
  (println msg)
  (System/exit status))

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
           (#{"start" "stop" "status"} (first arguments))) {:action (first arguments) :options options}
      :else {:exit-message (usage summary)})))

(defn certificaat [args]
  (let [{:keys [action options exit-message ok?]} (validate-args args)
        options (update-in options [:config-dir] #(str % (:domain options) "/"))]
    (if exit-message
      (exit (if ok? 0 1) exit-message)
      (case action
        "authorize" (println "authorize" options)
        "stop"   (println "request" options)
        "status" (println "status" options)))))
