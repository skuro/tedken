(ns tedken.core-test
  (:use [midje.sweet]
        [tedken.core])
  (:require [environ.core :refer [env]]
            [simple-time.core :as time]))

(defn insecure-request
  "Creates a RING request with no token"
  []
  {:method :post
   :headers []})

(defn secure-request
  "Creases a secure RING request that incoprorates the encrypted token for CSRF protection"
  []
  (let [response (add-token (insecure-request) (constantly "john") {})
        token (get-in response [:headers "X-CSRF-Token"])]
    {:method :post
     :headers {"X-CSRF-Token" token}}))

(defn dummy-handler
  "A dummy RING handler that always returns OK"
  [request]
  {:status 200
   :headers {}
   :body "Everything is ok!"})

(def secured-handler (wrap-csrf-token dummy-handler (constantly "john")))

(fact "Decode is the dual of encode"
      (decode (encode (.getBytes "test"))) => (fn [^bytes b] (= "test" (String. b))))

(fact "Decrypt is the dual of encrypt"
      (decrypt (encrypt "test")) => "test")

(fact "create-token is the dual of parse-token"
      (parse-token (create-token "one" "1234" "three")) => ["one" 1234 "three"])

(defn some-minutes-ago
  "Produces an epoch from some minutes ago"
  [minutes]
  (time/datetime->epoch (time/- (time/now)
                                (time/timespan 0 minutes 0))))

(defn now
  "Produces an epoch from now"
  []
  (time/datetime->epoch (time/now)))

(let [three-hours-ago        (some-minutes-ago (* 3 60))
      fifty-nine-minutes-ago (some-minutes-ago 59)
      one-hour-ago           (some-minutes-ago 60)]
  (fact "Old requests are invalid, but everything is recent within an hour"
        (actual? three-hours-ago)        => false
        (actual? one-hour-ago)           => false
        (actual? fifty-nine-minutes-ago) => true
        (actual? (now))                  => true))

(defn with-token
  "Creates a Ring request with the given token"
  [token]
  {:method :post
   :headers {"X-CSRF-Token" token}})

(let [right-user (create-token "john" (now) "fluff")
      wrong-user (create-token "tony" (now) "fluff")
      old-stamp  (create-token "john" (some-minutes-ago (* 3 60)) "fluff")]
  (facts "Requests are secured if the token contains the right user and an actual timestamp"
         (secured? (with-token right-user) (constantly "john")) => true
         (secured? (with-token wrong-user) (constantly "john")) => false
         (secured? (with-token old-stamp)  (constantly "john")) => false))

(defn token->user
  "Midje checker function that ensures the token is for the given user"
  [user]
  (fn [res]
    (let [token (get-in res [:headers "X-CSRF-Token"])
          [res-user _ _] (parse-token token)]
      (= user res-user))))

(fact "I can add tokens to the response"
      (add-token {} (constantly "john") {}) => (token->user "john"))
