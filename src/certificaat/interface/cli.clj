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
           (org.shredzone.acme4j.exception AcmeServerException AcmeUnauthorizedException AcmeRateLimitExceededException)
           org.shredzone.acme4j.Status))

(def cli-options
  [["-d" "--config-dir CONFIG-DIR" "The configuration directory for certificaat. Default follows XDG folders convention."
    :default (:config-dir c/defaults)
    :validate [#(s/valid? ::domain/config-dir %) "Must be a string"]]
   ["-m" "--domain DOMAIN" "The domain you wish to authorize"
    :validate [#(s/valid? ::domain/domain %) "Must be a valid domain"]]
   ["-n" "--san SAN" "Subject Alternative Name. Additional domain to be authorized. You can repeat this option."
    :parse-fn #(set [%])
    :assoc-fn (fn [m k v] (update-in m [k] #(into #{} (set/union % v))))
    :validate [#(s/valid? ::domain/san %) "Must be a valid domain"]]
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
        "Examples: certificaat -m change.me run"
        "          certificaat -m change.me -n www.change.me run "
        "          certificaat -m change.me -n www.change.me -n blog.change.me run "
        ""
        "Actions:"
        "  init   Run once for domain and optional san (Subject Alternative Names)."
        "  run    Run multiple times until certificate is acquired"
        "  cron   Renew certificate in cron jobs"
        "  info   Show certificate info (expiry date, etc.)"
        "  reset  Deletes data directory associated with domain and san"
        
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
    (doseq [[name auth challenges] (k/authorize options reg)
            i (range (count challenges))
            challenge challenges
            :let [explanation (k/explain challenge name)]]
      (println explanation)
      (spit (str config-dir domain "/" name "." (.getType challenge) ".challenge.txt") explanation)
      (spit (str config-dir domain "/challenge." name "." i ".uri") (.getLocation challenge))
      (spit (str config-dir domain "/authorization." name ".uri") (.getLocation auth)))))
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
      (catch AcmeRateLimitExceededException e (exit 1 (.getMessage e)))
      (catch AcmeUnauthorizedException e (exit 1 (.getMessage e)))) ))

(defn run [{config-dir :config-dir domain :domain :as options}]
  (cond
    (not (k/valid? (str config-dir "registration.uri") options)) (register options)
    (not (k/valid? (str config-dir domain "/authorization." domain ".uri") options)) (do (authorize options)
                                                                                         (h/run-hooks :before-challenge options))
    (or (k/pending? (str config-dir domain "/authorization." domain ".uri") options)
        (not (k/valid? (str config-dir domain "/certificate.uri") options))) (do (accept-challenges options)
                                                                               (request options)
                                                                               (h/run-hooks :after-request options))
    :else (exit 0 "Nothing left to do at this point in time.")))
(defn renew [{domain :domain config-dir :config-dir :as options}]
  (if (k/valid? (str config-dir domain "/authorization." domain ".uri") options)
    (request options)
    (do (authorize options)
        (h/run-hooks :before-challenge options)
        (accept-challenges options)
        (request options)))
  (h/run-hooks :after-request options))

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
                      (loop [t 3]
                        (if (> t 0)
                            (run options)
                            (exit 1 (str "Quitting for now")))
                        (recur (dec t)))) 
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
                 (renew options))))))
