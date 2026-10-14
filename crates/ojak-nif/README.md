ojak-nif
========

Ojak's signatures and JSON-LD, for Elixir.

An ActivityPub server written in Elixir already has what Elixir is good at:
processes, queues, supervision, and a network stack.  What it may not want to
write again is the part that is subtle and heavy: checking and making HTTP
signatures, object integrity proofs and Linked Data Signatures, and reading
JSON-LD.  This is that part, from *ojak-sig* and *ojak-jsonld*, as a NIF.

It does no I/O.  The application fetches keys and documents, queues and sends,
and keeps the time; this checks and makes.  *Delivery stays in Elixir*, with
its own retries and supervision, and asks this only for the headers to send.


Layout
------

 -  *src*: The NIFs.  They turn terms into values and results back into terms,
    and nothing else.
 -  *../ojak-nif-core*: What they do, in plain Rust, tested by `cargo test`.
    It is apart because a library that calls `enif_*` cannot be linked into a
    test binary.
 -  *elixir*: The Mix project.  `Ojak.Nif` documents each function and its
    types, and *elixir/test* tests the whole through a real VM.

The split follows [Feder]'s: protocol decisions as functions of the facts they
are given, with no state kept, and the platform around them.

[Feder]: https://github.com/fedify-dev/feder


Using it
--------

~~~~ sh
cd crates/ojak-nif/elixir
mix test
~~~~

`mix compile` runs `cargo build --release -p ojak-nif` and puts the library in
*priv*.  `OJAK_NIF_PROFILE=debug` builds without optimisation, which builds
faster and runs RSA far slower.  Erlang/OTP 22 or later, and Elixir 1.14 or
later, are needed; the Elixir side has no dependencies.

Checking a request is three steps, kept apart so that the application's own
work, fetching the actor, goes between them:

~~~~ elixir
request = {"POST", "/users/alice/inbox", headers, body}

with {:ok, signature, info} <- Ojak.Nif.signature_parse(request),
     :ok <- Ojak.Nif.signature_check(signature, request, ["example.com"], 3600, now),
     {:ok, key} when key != nil <- Ojak.Nif.published_key(actor, info.key_id),
     :ok <- Ojak.Nif.signature_verify(signature, request, key) do
  :verified
end
~~~~


How it behaves
--------------

 -  A JSON document is a map with string keys, as a JSON library gives it.
 -  Time is an argument, in seconds since the Unix epoch.
 -  Anything that can take a millisecond (RSA, JSON-LD, post-quantum
    signatures) runs on a dirty CPU scheduler.  Those are as many as the CPUs,
    so the application bounds the size of what it hands over.  The work a
    JSON-LD document may cause is bounded here too.
 -  Content that is wrong comes back as `{:error, reason}`.  Only a call of
    the wrong *shape* raises `ArgumentError`.
 -  A private key is parsed once into an opaque reference and does not come
    back out.
 -  A JSON-LD registry keeps the contexts it has processed, so a long-lived one
    is cheaper than a new one for each document.  Its cache is bounded, and
    belongs to it alone.
