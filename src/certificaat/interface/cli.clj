(ns certificaat.interface.cli
  (:require [certificaat.domain :as domain]
            [certificaat.fsm :as f]
            [certificaat.kung-fu :as k]
            [certificaat.utils :refer [exit error-msg]]
            [certificaat.util.configuration :as c]
            [certificaat.util.tentoonstelling :as t]
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

(defn certificaat [args]
  (let [{:keys [action options exit-message ok?]} (validate-args args)]
    (if exit-message
      (exit (if ok? 0 1) exit-message)
      (case action
        "init"      (let [cli-options (validate ::domain/cli-options options)
                          config-options (validate ::domain/config c/defaults)
                          options (merge config-options cli-options)]
                      (f/setup options))
        "run"       (let [cli-options (validate ::domain/cli-options options)
                          config-options (validate ::domain/config (c/read-config cli-options))
                          options (merge config-options cli-options)]
                      (when (> (:verbosity options) 0) (println options))
                      (try
                        (f/run options)
                        (catch AcmeUnauthorizedException e (println (.getMessage e))))) 
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
                 (f/renew options))))))
