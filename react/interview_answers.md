# Java — Core Interview Answers (Q1–50)

This document contains senior-level answers to common Core Java interview questions (questions 1–50). Each answer is concise but thorough, focusing on practical considerations, trade-offs, and where the topics matter in real systems.

## Table of Contents

1. What are the main OOP principles?
2. Difference between abstraction and encapsulation?
3. What is polymorphism with examples?
4. Method overloading vs overriding?
5. What is immutability?
6. How does HashMap work internally?
7. What happens when hash collisions occur?
8. ConcurrentHashMap vs HashMap?
9. Difference between ArrayList and LinkedList?
10. Comparable vs Comparator?
11. What is equals() and hashCode() contract?
12. How does Java memory management work?
13. Stack vs Heap memory?
14. What is garbage collection?
15. Types of garbage collectors?
16. What is JVM?
17. JDK vs JRE vs JVM?
18. What is classloader?
19. String pool concept?
20. Why String is immutable?
21. What is reflection?
22. What is serialization?
23. transient keyword?
24. volatile keyword?
25. synchronized keyword?
26. What is thread safety?
27. Runnable vs Callable?
28. Executor framework?
29. Future vs CompletableFuture?
30. Deadlock and prevention?
31. wait() vs sleep()?
32. notify vs notifyAll?
33. Atomic variables?
34. Functional interfaces?
35. Lambda expressions?
36. Streams API?
37. Intermediate vs terminal operations?
38. Optional class?
39. Generics?
40. Type erasure?
41. Exception hierarchy?
42. Checked vs unchecked exceptions?
43. try-with-resources?
44. Marker interfaces?
45. Annotations?
46. Design patterns in Java?
47. Singleton implementation?
48. Builder pattern?
49. Factory pattern?
50. Dependency injection concept?

---

### 1. What are the main OOP principles?

The four core OOP principles are Encapsulation (bundling state and behavior; controlling access via visibility and APIs), Abstraction (exposing essential behavior while hiding complexity), Inheritance (reusing and extending behavior via parent-child relationships), and Polymorphism (objects presenting different implementations through a common interface). At senior level, emphasize designing for composition over inheritance, using interfaces to define contracts, and leveraging encapsulation to maintain invariants and evolve internals without breaking clients.

### 2. Difference between abstraction and encapsulation?

Abstraction is about modeling — exposing what an object does (its public contract) while hiding internal complexity. Encapsulation is about protection — bundling data with methods and restricting direct access (private fields, controlled setters). Practically, abstraction drives API design and encapsulation enforces invariants and prevents misuse. Both are used together: an abstract interface defines the contract and encapsulation hides the concrete implementation.

### 3. What is polymorphism with examples?

Polymorphism lets code operate on objects through a common type while concrete behavior varies at runtime. Examples: subtype polymorphism (interface List with ArrayList/LinkedList implementations), overridden methods (a Service interface with different implementations selected via DI), and parametric polymorphism via generics (List<T>). At runtime, virtual dispatch selects the correct override; at design time, polymorphism enables loose coupling and easier testing.

### 4. Method overloading vs overriding?

Overloading is compile-time: same method name but different parameter lists in the same class (or subclass). Overriding is runtime polymorphism: a subclass provides a different implementation for a method declared in a superclass or interface (same signature). Overriding affects behavior via dynamic dispatch; overloading is syntactic convenience resolved at compile time.

### 5. What is immutability?

An immutable object cannot change state after construction. Immutability simplifies reasoning about concurrency, caching, and equality. Implement via final fields, no mutators, defensive copying, and careful handling of mutable internals. Use immutable value objects (String, BigInteger) for safety; prefer immutable APIs when possible and document construction costs for large objects.

### 6. How does HashMap work internally?

A HashMap stores entries in an array of buckets; keys are hashed and mapped to a bucket index. Within each bucket entries are chained (historically linked lists, converted to balanced trees for long chains in modern JDKs). On get/put, HashMap computes hash, finds the bucket, and either searches linearly (list) or via tree lookup. It resizes (rehashes) when load factor threshold reached, which is an O(n) operation intermittently. Pay attention to proper hashCode implementations and initial capacity to avoid resizing and collisions in high-throughput systems.

### 7. What happens when hash collisions occur?

Collisions map multiple keys to the same bucket. HashMap stores colliding entries in a chain; for small chains it uses a linked list and switches to a balanced tree (TreeNode/Red-Black) when chain length surpasses a threshold. Collisions increase lookup time and can be exploited by attackers, so use well-distributed hash functions and consider limiting exposure in web APIs (e.g., use concurrent data structures or defend against untrusted-key DOS).

### 8. ConcurrentHashMap vs HashMap?

HashMap is not thread-safe; concurrent access can corrupt internal structures. ConcurrentHashMap is designed for concurrency: earlier versions partitioned buckets into segments, modern implementations use lock-striping and CAS for finer-grained concurrency without locking the whole map. ConcurrentHashMap provides eventual consistency for size(), no locking for reads, and weakly consistent iterators. Use ConcurrentHashMap for high-concurrency caches and maps; use Collections.synchronizedMap only for simpler, coarser synchronization needs.

### 9. Difference between ArrayList and LinkedList?

ArrayList is an array-backed list offering O(1) random access and amortized O(1) append; removals/inserts away from tail are O(n) due to shifting. LinkedList is a doubly-linked list offering O(1) insert/remove with a known node reference but O(n) random access. For most use-cases ArrayList is preferred because of better locality and lower overhead; use LinkedList only when you have many insertions/removals at known positions and heavy iterator-based manipulations.

### 10. Comparable vs Comparator?

Comparable defines a natural ordering on objects via a compareTo method (class-level). Comparator is a strategy object that defines an external ordering and can be supplied when sorting or ordering is needed. Prefer Comparator for multiple orderings and to avoid coupling model classes to a single sort order. Use static factory methods like Comparator.comparing for concise, null-safe comparators.

### 11. What is equals() and hashCode() contract?

The contract: if two objects are equal according to equals(), they must have the same hashCode(). hashCode() does not need to be unique, but must be consistent across invocations while the object state used in equals/hashCode remains unchanged. Violating the contract breaks hash-based collections. Implement both together, prefer final fields for equality, and consider using IDE-generated or library helpers (Objects.equals/hash) to avoid subtle bugs.

### 12. How does Java memory management work?

Java memory is managed by the JVM: code and data live in regions like the heap (objects), stack (frames/local primitives), metaspace (class metadata), and native memory. The GC reclaims unreachable objects on the heap. Developers control object lifetime indirectly by dropping references, tuning GC, and using appropriate data structures. Heap sizing, young/old generation ratios, and GC algorithm choice are key levers for performance and latency.

### 13. Stack vs Heap memory?

Stack holds method frames, local variables, and reference values — it's thread-local and short-lived. Heap stores objects and arrays, shared across threads, and managed by GC. Stack allocation is fast and deterministic; heap allocation is cheaper than freeing thanks to GC but can incur pauses for collection. Avoid large objects on the stack (not possible) and be mindful of reference lifetimes to prevent memory leaks.

### 14. What is garbage collection?

Garbage collection is the automated process in the JVM that reclaims memory occupied by objects that are no longer reachable from GC roots. GC algorithms identify live objects via root tracing and reclaim unreachable memory, optionally compacting the heap. GC relieves developers from manual memory management but requires tuning for performance-sensitive systems to control pause times and throughput.

### 15. Types of garbage collectors?

Common JVM collectors: Serial (single-threaded, simple), Parallel (throughput-oriented), CMS (concurrent low-pause, older), G1 (regional, balanced latency/throughput), ZGC and Shenandoah (low-pause collectors using concurrent compaction). Choose based on latency requirements: G1/ZGC for low-latency large heaps; Parallel for batch throughput; tune generations, GC threads, and ergonomics accordingly.

### 16. What is JVM?

JVM (Java Virtual Machine) is the runtime that loads bytecode, verifies it, JIT-compiles hotspots to native code, manages memory and threads, and provides platform abstraction. It includes subsystems: class loader, garbage collector, JIT compiler, and runtime services. Understanding JVM behavior (JIT, GC, memory layout) is vital for diagnosing performance issues in production.

### 17. JDK vs JRE vs JVM?

JVM is the runtime engine. JRE (Java Runtime Environment) bundles the JVM and standard libraries required to run Java programs. JDK (Java Development Kit) includes the JRE plus development tools (javac, jar, jdb). For production, run on a JRE/JDK distribution tailored to your CI/CD and runtime needs; many deployments use a trimmed JRE or container images with only required modules.

### 18. What is classloader?

A classloader loads classes and resources into the JVM, converting binary class data into Class objects. Java uses a delegation model (bootstrap, extension/platform, application) to avoid multiple copies and ensure core classes are loaded by trusted loaders. Custom classloaders support plugin systems, hot reloading, and isolation; they must handle security, resource lookup, and parent delegation carefully to avoid leaks and conflicts.

### 19. String pool concept?

The String pool (intern pool) stores unique string literals to save memory and allow fast equality checks by reference. String literals and interned strings share instances; calling intern() adds a string to the pool. Use it for many repeated literals, but beware of large pools causing memory pressure. Since strings are immutable, pooling is safe; prefer intern for a controlled set of frequently used, repeated values.

### 20. Why String is immutable?

Strings are immutable to enable safe sharing, caching (hashCode), and use as keys in collections. Immutability prevents accidental modification across consumers and simplifies concurrency (no synchronization required). It also enables optimizations like string pooling and secure APIs (e.g., passing strings to sensitive methods without copying). For mutable text, use StringBuilder or StringBuffer (thread-safe but slower).

### 21. What is reflection?

Reflection is the runtime inspection and manipulation of classes, methods, fields, and annotations. It enables frameworks, DI containers, and serializers to operate without compile-time coupling. Reflection is powerful but costly (performance), bypasses encapsulation (can break invariants), and interacts with security managers; use it judiciously and cache reflective lookups for performance.

### 22. What is serialization?

Serialization converts an object graph to a byte-stream for persistence or transmission; deserialization reconstructs it. Java's built-in serialization (Serializable) is flexible but fragile and risky (security, versioning). Prefer explicit, versioned formats (JSON, protobuf) or custom serialization mechanisms with schema evolution and clear compatibility guarantees for production systems.

### 23. transient keyword?

`transient` marks fields to be skipped during Java serialization. Use for derived state, non-serializable handles, or security-sensitive data (passwords). When deserialized, transient fields get default values; implement readObject/writeObject or use custom serializers if you need controlled restoration.

### 24. volatile keyword?

`volatile` ensures visibility of writes to other threads and prohibits certain reordering; reads/writes to volatile variables have memory visibility guarantees but are not atomic for compound operations. Use volatile for flags or single-writer/multiple-reader patterns; for atomic increments or compound state, prefer Atomic* classes or locks.

### 25. synchronized keyword?

`synchronized` provides mutual exclusion and establishes a happens-before relationship for visibility. It can be applied to methods or blocks. Modern JVMs optimize uncontended synchronized paths, but locks still have overhead and can cause contention; prefer higher-level concurrency primitives (Lock, ReadWriteLock, concurrent collections) when appropriate.

### 26. What is thread safety?

Thread safety means correct behavior when accessed concurrently. Strategies include immutability, confinement (thread-local), synchronization, lock-free algorithms (Atomics), and using concurrent collections. At senior level, design for minimal locking regions, prefer well-tested concurrency primitives, and reason about liveness (deadlocks) and fairness when choosing synchronization approaches.

### 27. Runnable vs Callable?

Runnable represents a task with no return value and cannot throw checked exceptions. Callable returns a result and can throw checked exceptions. Use Callable when you need a result or exception propagation; submit Callables to ExecutorService to obtain Futures for results and cancellation control.

### 28. Executor framework?

The Executor framework decouples task submission from execution. ExecutorService, ThreadPoolExecutor, and ScheduledThreadPoolExecutor provide thread pooling, queuing, rejection policies, and lifecycle management. Tune pool sizes, queue types (bounded vs unbounded), and rejection handlers based on workload characteristics (IO-bound vs CPU-bound) and implement graceful shutdown for production systems.

### 29. Future vs CompletableFuture?

Future represents a pending result with blocking get(); it has limited composition. CompletableFuture provides non-blocking composition, async callbacks, combinators (thenApply, thenCombine), and explicit completion. Use CompletableFuture for reactive-style, asynchronous flows and to build complex pipelines without blocking threads.

### 30. Deadlock and prevention?

Deadlock occurs when threads wait cyclically for locks. Prevent using strategies: acquire locks in a consistent global order, use tryLock with timeouts, minimize lock scope, prefer lock ordering or lock coupling, and detect via monitoring (thread dumps). Design systems to avoid long-held locks and prefer non-blocking algorithms when low latency is critical.

### 31. wait() vs sleep()?

`sleep()` pauses the current thread for a duration without releasing locks. `wait()` (Object.wait) releases the monitor and suspends until notified; it's used for inter-thread coordination with notify/notifyAll and requires owning the object's monitor. Use wait/notify for condition-based waits and sleep for timed pauses unrelated to lock semantics.

### 32. notify vs notifyAll?

`notify()` wakes a single waiting thread; `notifyAll()` wakes all waiting threads on the monitor. Use notifyAll() when multiple conditions exist or to avoid lost wakeups and subtle bugs; notify() can be more efficient but can cause missed signals if used incorrectly. Prefer higher-level concurrency constructs (Condition, BlockingQueue) for clearer semantics.

### 33. Atomic variables?

Atomic classes (AtomicInteger, AtomicReference, etc.) provide lock-free, CAS-based operations for atomic updates and are useful for counters, flags, and simple state management. They reduce contention and provide better scalability than locks for certain patterns, but for complex invariants use locks or transactional approaches. Beware of ABA problems for CAS on raw references; AtomicStampedReference can help.

### 34. Functional interfaces?

A functional interface has a single abstract method and can be instantiated with a lambda or method reference (e.g., Runnable, Function<T,R>). They enable concise behavior passing and are central to streams and modern API design. Use @FunctionalInterface for clarity and to maintain compatibility during evolution.

### 35. Lambda expressions?

Lambdas are lightweight function literals that implement functional interfaces; they improve readability and reduce boilerplate. Under the hood, the JVM may generate invokedynamic call sites or synthetic classes; capturing lambdas may allocate objects. Use them for concise callbacks, functional composition, and stream pipelines.

### 36. Streams API?

Streams provide a declarative pipeline for transforming and processing collections (map/filter/reduce). Streams separate data source from computation, support lazy evaluation, and parallel execution via parallelStream. For large-scale systems, measure overhead vs manual loops, avoid shared mutable state in parallel streams, and prefer collections optimized for parallel processing.

### 37. Intermediate vs terminal operations?

Intermediate operations (map, filter) are lazy and return another stream; they build the pipeline. Terminal operations (collect, forEach, reduce) trigger evaluation and produce results. This lazy evaluation enables optimization like short-circuiting and fusion; design pipelines to minimize work and avoid side effects.

### 38. Optional class?

Optional is a container that may hold a non-null value, used to avoid nulls and convey optionality in APIs. Use Optional for return values (not for fields/parameters typically) and prefer map/flatMap/orElse patterns over direct isPresent checks. Avoid overuse that complicates callers; it's an API-level tool for clearer contracts.

### 39. Generics?

Generics provide compile-time type safety and reusability (List<String>). They enable a single implementation to work across types. At runtime, type information is erased (type erasure), so operations that depend on runtime types require care (casts, instanceof with generics). Use bounded wildcards (<? extends T>, <? super T>) to express variance in APIs.

### 40. Type erasure?

Type erasure removes generic type parameters at runtime, replacing them with their bounds (usually Object). This maintains backward compatibility but limits runtime type checks and prevents creating generic arrays. Workarounds include passing Class<T> tokens, using explicit converters, or designing APIs that avoid needing runtime generic type information.

### 41. Exception hierarchy?

Java exceptions derive from Throwable, split into Exception (checked) and Error (serious JVM problems). RuntimeException and its subclasses are unchecked errors caused by programmer mistakes. Design APIs to throw meaningful exceptions, favor unchecked exceptions for programming errors, and use checked exceptions when the caller can reasonably recover.

### 42. Checked vs unchecked exceptions?

Checked exceptions are part of method signatures and force the caller to handle or declare them; unchecked exceptions (RuntimeException) do not. Use checked exceptions for recoverable, expected failure modes (I/O issues) and unchecked for unrecoverable programming errors (NullPointerException). Overusing checked exceptions can clutter APIs; balance clarity and ergonomics.

### 43. try-with-resources?

Try-with-resources ensures deterministic closing of AutoCloseable resources and simplifies exception handling by suppressing secondary exceptions properly. Prefer it for I/O, JDBC, and similar resources to avoid leaks. For complex cleanup, consider explicit resource managers when lifecycle is non-local.

### 44. Marker interfaces?

Marker interfaces (Serializable, Cloneable) convey metadata without methods. They signal special treatment by frameworks or the runtime. Prefer annotations or explicit interfaces with behavior for clearer intent; marker interfaces are legacy in many cases but still used by core APIs.

### 45. Annotations?

Annotations provide metadata for code (runtime or compile-time) used by frameworks, tools, and the compiler. Use them to declare behavior (DI, validation, mapping). Design custom annotations with retention and target policies, keep them small, and document semantics for tooling and backward compatibility.

### 46. Design patterns in Java?

Common patterns: Singleton, Factory, Builder, Strategy, Observer, Decorator, Adapter, Repository, and Dependency Injection. Use patterns as communication tools; avoid overusing them — prefer simple, composable designs. At senior level, select patterns that improve testability, modularity, and explicit responsibilities.

### 47. Singleton implementation?

Preferred implementation is the enum-based singleton (Joshua Bloch): it’s simple, provides serialization guarantee, and resists reflection-based attacks. Alternatives include private constructor + static factory with final instance or lazy holder idiom. Understand when singletons introduce global state and consider dependency injection for better testability.

### 48. Builder pattern?

Builder separates complex object construction from representation, improving readability and immutability for objects with many optional parameters. Use static nested Builder classes or libraries (AutoValue, Lombok) to reduce boilerplate. Builders improve API stability and are especially useful for domain objects and configuration components.

### 49. Factory pattern?

Factory encapsulates object creation, decoupling clients from concrete implementations. Use simple factories or abstract factories for families of related objects. Combine with DI to wire concrete types; factories are useful when creation involves logic, caching, or type selection.

### 50. Dependency injection concept?

Dependency Injection (DI) inverts control of creating dependencies — objects receive collaborators from an external injector (constructor, setter, field). DI improves modularity, testability, and configuration flexibility. Use constructor injection for mandatory dependencies, prefer explicit wiring via frameworks (Spring, Guice) or lightweight factories, and avoid service locators that hide dependencies.

## Section 2 — Spring Boot / Backend (Q51–Q75)

### 51. What is Spring Boot?

Spring Boot is an opinionated framework built on Spring that accelerates application development by providing auto-configuration, sensible defaults, and embedded runtime components (Tomcat/Jetty/Netty). It removes boilerplate configuration required to bootstrap a Spring application, offering starters (pom dependencies) that aggregate commonly used libraries and auto-configure beans based on classpath contents and properties. For production-grade systems, Spring Boot streamlines common operational concerns: externalized configuration via `application.properties`/`application.yml`, health checks through Actuator, metrics integration, and easy packaging into executable JARs/containers.

At a senior level, emphasize Spring Boot's value in reducing plumbing and enforcing conventions while also noting pitfalls: auto-configuration can hide complexity and couple behavior to classpath composition, so explicit configuration and understanding the auto-configured beans are essential for predictable behavior. Use `spring.factories`/`@EnableAutoConfiguration` patterns when building custom starters and prefer configuration properties classes for type-safe config binding.

### 52. How does Spring Boot work internally?

Spring Boot coordinates a startup sequence that discovers and registers auto-configuration classes, loads application properties, and initializes an ApplicationContext. Key steps: the `SpringApplication` class sets up the environment, reads `application.properties`/`yaml`, selects an `ApplicationContext` implementation (e.g., `AnnotationConfigApplicationContext` for standard apps or `SpringApplication.run` which creates a `SpringApplication`), and triggers auto-configuration via `@EnableAutoConfiguration` which is driven by `spring.factories`. Auto-configuration classes are conditional (via `@ConditionalOnMissingBean`, `@ConditionalOnClass`, etc.), meaning they only create beans when their conditions match the runtime environment.

Internally, Spring Boot registers `BeanFactoryPostProcessor` and `BeanPostProcessor` implementations that manipulate bean definitions and instances before and after initialization. The embedded server (Tomcat/Jetty/Netty) is auto-configured and started as part of context refresh. Actuator endpoints and metrics are registered via conditional configuration. For production, inspect the auto-configurations (`/config`) and use `spring.main.banner-mode=off`, `management.endpoints.web.exposure.include`, and `debug=true` to diagnose what Boot auto-configured.

### 53. What is dependency injection?

Dependency Injection (DI) is a design pattern where an external component (the container or injector) provides an object's dependencies rather than the object creating them. The goal is to invert control of dependency creation and wiring, enabling loose coupling, easier testing (by injecting mocks), and centralized configuration. DI can be achieved via constructor injection (preferred for required dependencies), setter injection (for optional/late-bound dependencies), or field injection (less preferred due to reduced testability and hidden dependencies).

In Spring, DI is implemented by the IoC container: annotated components (`@Component`, `@Service`, `@Repository`, `@Controller`) or explicit `@Bean` methods are discovered and registered; the container resolves dependencies by type (and optionally by qualifier or name) and injects them at creation time. For complex setups use `@Configuration` classes with factory methods, explicit `@Qualifier` and `@Primary` rules, and prefer constructor injection for immutability and simpler unit testing. At scale, DI reduces boilerplate, but be mindful of overly broad component scanning and cyclic dependencies which indicate design smells.

### 54. Bean lifecycle?

A Spring bean undergoes a well-defined lifecycle managed by the ApplicationContext. Lifecycle stages: instantiation (constructor or factory method), dependency injection (setting properties or constructor args), `BeanPostProcessor` pre-initialization callbacks, `@PostConstruct` (or custom `init-method`), initialization callbacks and `BeanPostProcessor` post-initialization, usage, and finally destruction (`@PreDestroy` or `destroy-method`) when the context shuts down. For prototype-scoped beans the container performs instantiation and dependency injection but does not manage the full lifecycle or destruction.

At senior level, understand extension points: `BeanFactoryPostProcessor` modifies bean definitions before bean creation; `BeanPostProcessor` intercepts instances before/after initialization (used by AOP proxies, proxy creation, and @Autowired processing). Use `SmartInitializingSingleton` for logic to run after all singletons are initialized, and `DisposableBean`/`InitializingBean` for lifecycle hooks when necessary. Keep lifecycle callbacks minimal — favor explicit initialization via factory methods for testability.

### 55. @Component vs @Service vs @Repository?

All three are stereotypes and functionally similar (they mark classes as candidates for component scanning). `@Component` is a generic stereotype. `@Service` indicates service-layer semantics (business logic), and `@Repository` signals persistence-layer components and has special translation semantics: Spring wraps `@Repository`-annotated classes to translate persistence exceptions into Spring's `DataAccessException` hierarchy. Use `@Repository` for DAOs, `@Service` for business services, and `@Component` for lower-level or cross-cutting components.

From a design perspective, using specific stereotypes improves readability and enables framework behavior (exception translation), while facilitating systematic component scanning and clearer package organization.

### 56. @Autowired vs constructor injection?

`@Autowired` is Spring's annotation for dependency injection. It can be applied to fields, setters, or constructors. Constructor injection (either via `@Autowired` on a constructor or simply a single constructor without `@Autowired` in recent Spring versions) is the recommended approach: it makes dependencies explicit, works well with immutability, and simplifies unit testing. Field injection hides dependencies and complicates testing and object creation outside the container.

Constructor injection also prevents partially-initialized objects and eliminates the possibility of circular dependencies at runtime (forcing you to address them during design). Use `@Autowired(required=false)` or `Optional<T>` for optional dependencies, but prefer explicit configuration and fallback beans for clarity.

### 57. @Configuration vs @Bean?

`@Configuration` marks a class as a source of bean definitions; methods annotated with `@Bean` inside a `@Configuration` class declare bean factory methods. `@Configuration` classes are enhanced (CGLIB proxies) so that `@Bean` methods are singletons by default and calls between `@Bean` methods go through the container to ensure shared instances. Using `@Component` plus `@Bean` in non-`@Configuration` classes (or `@Configuration(proxyBeanMethods=false)`) changes semantics and avoids proxying when you don't need inter-bean references.

Prefer `@Configuration` for explicit wiring, reuse, and when you require container-managed singleton behavior. For lightweight factory methods prefer `@Component` with `@Bean` or `@Import` as appropriate.

### 58. What is IoC container?

The Inversion of Control (IoC) container is the core of the Spring framework that manages bean creation, wiring, lifecycle, and configuration. It reads bean definitions (annotations, XML, `@Bean` methods), resolves dependencies, applies post-processors, and provides the ApplicationContext for retrieving beans and resources. The container decouples object creation from use, enabling features like AOP, transaction management, and scoped proxies. For large applications, understand the container's memory footprint and startup cost; use lazy initialization, profile-based beans, and conditional beans to reduce resource usage.

### 59. What is Spring MVC?

Spring MVC is a request-driven web framework built on the DispatcherServlet front controller pattern. It maps HTTP requests to controller handler methods (annotated with `@Controller`/`@RequestMapping`), converts request data to method arguments via `HandlerMethodArgumentResolver`s, performs validation, and resolves views via `ViewResolver`s (Thymeleaf, JSP) or returns data for REST controllers (`@ResponseBody`/`@RestController`). Spring MVC is highly configurable with interceptors, filters, message converters (JSON/XML), and content negotiation.

Design considerations: separate web concerns (controllers) from services, use DTOs for request/response shapes, validate at the boundary, and keep controllers thin. For high-throughput APIs, prefer lightweight serialization configuration and tune connection/thread pools at the servlet container level.

### 60. DispatcherServlet flow?

`DispatcherServlet` is the central servlet that receives incoming HTTP requests and dispatches them to registered handlers. Flow: request arrives → `DispatcherServlet` receives it → determines `HandlerMapping` to find a handler (controller) → obtains a `HandlerAdapter` to invoke the handler method → handler executes business logic → returns a `ModelAndView` or response body → `ViewResolver` renders a view (or `HttpMessageConverter` writes body) → response returned. Along the way, `HandlerInterceptors` can pre/post-process requests, and exceptions are handled via `HandlerExceptionResolver` or `@ControllerAdvice`.

Internally, HandlerMapping implementations (e.g., `RequestMappingHandlerMapping`) inspect controller annotations; the adapter (`RequestMappingHandlerAdapter`) handles argument resolution, data binding, validation, and return value handling. For production, tune servlet thread pools and avoid blocking operations in controller threads.

### 61. @RestController vs @Controller?

`@Controller` marks a class as an MVC controller and typically returns views; methods annotated with `@ResponseBody` return raw responses. `@RestController` is a convenience annotation that combines `@Controller` and `@ResponseBody`, making methods return serialized objects (usually JSON) directly. Use `@RestController` for REST APIs and `@Controller` when serving server-side rendered views. Keep controllers focused on request handling and delegate business logic to service layers.

### 62. Request lifecycle in Spring?

A typical request lifecycle: incoming HTTP request → servlet container hands to `DispatcherServlet` → preHandle interceptors → handler mapping → controller invocation (argument resolution, validation) → service layer processing → controller return (ModelAndView or body) → view resolution or message conversion → postHandle interceptors → `DispatcherServlet` completes and triggers after-completion interceptors. Throughout this lifecycle, exception resolvers and filters may intervene. For tracing and observability, integrate interceptors or filters to capture correlation IDs and timing metrics.

### 63. Filters vs Interceptors?

Filters (Servlet API) operate at the container level and can modify request/response streams, apply to any servlet-based component, and run before Spring MVC is initialized. Interceptors (`HandlerInterceptor`) are Spring MVC-specific and work at the handler invocation level, providing preHandle/postHandle/afterCompletion hooks with access to handler metadata. Use filters for cross-cutting concerns that require access to raw request/response (e.g., request wrapping, security at the servlet layer), and interceptors for handler-level concerns like authorization checks, request metrics, or adding model attributes.

### 64. HandlerInterceptor usage?

`HandlerInterceptor` provides preHandle/postHandle/afterCompletion hooks around controller execution. Use it for authentication/authorization checks, request-scoped logging, measuring execution time, and adding common model attributes for views. Because interceptors have access to handler metadata and resolved handler methods, they are ideal for cross-cutting web concerns that depend on controller context. For async requests, be mindful of thread context and clean up in `afterCompletion`.

### 65. Exception handling in Spring?

Spring offers multiple strategies: controller-level `@ExceptionHandler` methods, global `@ControllerAdvice` classes for cross-cutting exception handling, and `HandlerExceptionResolver` implementations. For REST APIs, map exceptions to meaningful HTTP status codes and standard error payloads. Capture and log stack traces centrally with correlation IDs, and avoid leaking internal implementation details in responses. Prefer explicit exception hierarchies (e.g., `EntityNotFoundException`, `ValidationException`) and map them consistently to clients.

### 66. @ControllerAdvice?

`@ControllerAdvice` is a specialized component for global exception handling, model attribute population, and binding configuration across controllers. It centralizes `@ExceptionHandler`, `@InitBinder`, and `@ModelAttribute` methods so you can return consistent error responses and apply cross-cutting request handling. Use it to enforce API error formats, default validation messages, and to attach global attributes like user info when rendering views.

### 67. @Transactional working?

`@Transactional` demarcates transactional boundaries. Spring implements it via proxies (AOP) that start a transaction before method execution and commit or rollback afterward based on exceptions and propagation rules. Transactions are managed by a `PlatformTransactionManager` (e.g., `DataSourceTransactionManager`, `JpaTransactionManager`) which interacts with JDBC connections or JPA `EntityManager`s. Transactions control isolation, rollback rules, and timeout behavior.

Key considerations: `@Transactional` is only effective on public methods invoked through the proxy; self-invocation bypasses the proxy and won't start a transaction. For read-only operations, set `readOnly=true` to hint optimizations. Keep transactional boundaries coarse enough to maintain consistency but small enough to reduce lock contention.

### 68. Propagation types?

Propagation controls how transactional contexts are handled when a transactional method calls another transactional method. Common types: `REQUIRED` (join existing transaction or create new), `REQUIRES_NEW` (suspend existing and create new transaction), `SUPPORTS` (execute within existing or non-transactional if none), `MANDATORY` (must have existing transaction), `NOT_SUPPORTED` (suspend existing and execute non-transactionally), `NEVER` (throw if transaction exists), and `NESTED` (create a nested savepoint-based transaction when supported). Choose propagation based on isolation needs, compensating actions, and failure semantics — `REQUIRES_NEW` is useful for independent work (audit logs) that must persist even if caller rolls back.

### 69. Isolation levels?

SQL isolation levels define visibility of transactional changes and control phenomena like dirty reads, non-repeatable reads, and phantom reads. Common levels: `READ_UNCOMMITTED`, `READ_COMMITTED`, `REPEATABLE_READ`, `SERIALIZABLE`. Each level trades off concurrency and consistency; databases implement them differently (e.g., Oracle's `READ_COMMITTED` vs PostgreSQL's MVCC). In Spring set isolation on `@Transactional` when you need stronger guarantees; otherwise rely on default DB isolation and design for eventual consistency where appropriate.

### 70. Lazy vs eager loading?

Lazy loading defers fetching related entities until accessed; eager loading fetches associations immediately. Lazy reduces initial query cost but can cause N+1 query problems when iterating collections, while eager loading can result in over-fetching and large payloads. Use DTO projections, fetch joins, or batch fetching to balance performance. For REST APIs, avoid returning lazy entities directly — map to DTOs and control fetch semantics in queries.

### 71. Hibernate session lifecycle?

The Hibernate `Session` (or JPA `EntityManager`) represents a unit of work and maintains a first-level cache of managed entities. Typical lifecycle: open session/EM → begin transaction → perform CRUD/load operations (entities become managed) → flush (synchronize state with DB) → commit/rollback → close session. In Spring, sessions are usually bound to a transaction and managed by `JpaTransactionManager`. Be mindful of session-per-request patterns, lazy loading outside session scope (LazyInitializationException), and long sessions causing memory growth. Use explicit DTO queries or fetch strategies to control loading.

### 72. JPA vs Hibernate?

JPA is a specification (API) for ORM in Java; Hibernate is a mature implementation of JPA with additional features beyond the spec (Criteria API extensions, better caching, tooling). Design to the JPA API for portability, but leverage Hibernate-specific optimizations (second-level cache, stateless sessions, multi-tenancy) when needed. Using provider-specific features couples you to the implementation but can yield significant performance or operational benefits.

### 73. Entity states?

JPA entity states: transient (new, not associated with a persistence context), managed/persistent (attached to a session), detached (previously managed but no longer attached), and removed (scheduled for deletion). Transitions occur via `persist`, `merge`, `remove`, and on transaction commit. Understanding these states is essential for correct merging semantics, avoiding unintended updates, and managing identity and equality semantics.

### 74. N+1 problem?

The N+1 problem occurs when an initial query loads N parent entities and then issues additional queries per entity to load child associations, resulting in N+1 queries and poor performance. Prevent it with fetch joins (`JOIN FETCH`), batch fetching, entity graphs, or DTO projection queries that retrieve required data in a single optimized query. Monitor SQL in production and use profiling to detect N+1 patterns; fix at the query layer rather than by increasing hardware.

### 75. Fetch types?

Fetch types (LAZY, EAGER) control when associations are loaded. `LAZY` defers loading until accessed; `EAGER` loads associations immediately with the owning entity. Defaults differ (e.g., `@ManyToOne` often defaults to EAGER historically, but best practice is to prefer `LAZY` and fetch explicitly). Use DTO projections, fetch joins, and query tuning to control the actual SQL executed and avoid unexpected data loading and serialization issues.

## Section 2B — Spring Boot / Backend (Q76–Q100)

### 76. Pagination in Spring?

Pagination in Spring is typically handled via the Spring Data abstractions: `Pageable` and `Page<T>`. Repositories extending `PagingAndSortingRepository` or `JpaRepository` accept a `Pageable` parameter and return a `Page` object that includes content, total elements, total pages, and paging metadata. For APIs, expose page number and size parameters (or use cursor-based tokens for high-scale systems) and validate input to prevent expensive queries. Use `Slice<T>` for streamed access when you only need the next page without total counts — it avoids the extra `COUNT` query which can be costly on large tables.

From a senior perspective, design pagination for the workload: OFFSET-based pagination is simple but suffers from poor performance on deep pages; keyset (cursor) pagination scales better for large datasets and streaming UIs. Implement sorting guarantees (stable, deterministic order), avoid client-driven arbitrary sorts on large datasets without indices, and consider projection queries to reduce payload size.

### 77. DTO vs Entity?

DTOs (Data Transfer Objects) and Entities serve different responsibilities: Entities model persistence concerns and lifecycle (managed state, lazy loading, relationships), while DTOs model API contracts or service boundaries. Exposing entities directly from controllers couples your API to the persistence model, risks lazy-loading exceptions, and may leak internal fields or security-sensitive data. Using DTOs enables shape optimization, versioning, and decoupling from ORM semantics.

At senior level, prefer mapping layers (MapStruct, custom mappers) to translate between Entities and DTOs, keep DTOs immutable where possible, and define explicit DTO versions for breaking changes. For performance-critical flows, use JPA projections or constructor queries to populate DTOs directly from SQL to avoid the cost and side effects of entity hydration.

### 78. Validation annotations?

Spring integrates with the Bean Validation API (JSR 380 — Hibernate Validator implementation) to declaratively validate DTOs and entities using annotations like `@NotNull`, `@Size`, `@Pattern`, `@Email`, and custom constraints. Use `@Valid` on controller method parameters to trigger validation. For complex rules, implement `ConstraintValidator` classes or group validations using validation groups.

Senior considerations: keep validation at the boundary (controller/service) and separate cross-field or business validation into service-layer checks rather than relying solely on annotations. Provide consistent error formats (structured validation error responses), localize messages via `ValidationMessages.properties`, and avoid using entity annotations for API validation if entity lifecycle diverges from API contract.

### 79. Spring Security basics?

Spring Security provides a comprehensive framework for authentication, authorization, and security-related concerns. Core concepts: `Authentication` (who the user is), `Authorization` (what they're allowed to do), `SecurityContext` (where the current principal is stored), and filters that intercept requests to perform authentication/authorization. Configure security via `WebSecurityConfigurerAdapter` (legacy) or the newer component-based DSL (`SecurityFilterChain` beans) and define authentication providers (in-memory, JDBC, LDAP, OAuth2).

At senior level, design defense-in-depth: enforce least privilege, use method-level security (`@PreAuthorize`) for fine-grained rules, centralize access rules, and use strong password storage (bcrypt/argon2). For microservices, prefer token-based authentication (JWT or opaque tokens validated centrally) and apply authorization at both API gateway and service boundary levels.

### 80. JWT authentication?

JWT (JSON Web Token) is a compact, self-contained token format carrying claims (subject, expiry, roles) and signed (HMAC or asymmetric keys). In Spring Security, JWTs are typically issued by an auth server at login and validated by resource services using the signing key or JWKS endpoint. JWTs enable stateless authentication: services don't need server-side sessions, which simplifies scaling and reduces central state.

Senior-level caveats: JWTs can't be revoked easily unless you maintain a token blacklist or use short expirations with refresh tokens. Use short-lived access tokens and rotate/secure refresh tokens; prefer asymmetric signing (RS256) for distributed architectures with multiple verifiers. Validate token expiry, audience, issuer, and signature, and avoid storing sensitive data in token claims.

### 81. OAuth basics?

OAuth 2.0 is an authorization framework enabling third-party apps to obtain limited access to resources on behalf of users. Key flows include Authorization Code (with PKCE for public clients), Client Credentials (machine-to-machine), and Refresh Token handling. OAuth separates authentication (often implemented via OpenID Connect) from authorization concerns.

At senior level, implement the appropriate grant for your scenario (Authorization Code + PKCE for SPAs/mobile, Client Credentials for backend services). Treat tokens as bearer tokens and protect transport with TLS. Use scopes to represent coarse-grained access, combine with fine-grained authorization in resource servers, and centralize token issuance and validation in a trusted auth server.

### 82. CSRF protection?

Cross-Site Request Forgery (CSRF) is an attack where a malicious site causes a user's browser to perform state-changing requests on a site where they're authenticated. CSRF protection relies on ensuring requests include a secret not accessible to third-party sites: synchronizer tokens (CSRF tokens), same-site cookies, or requiring explicit user interaction.

Spring Security enables CSRF protection by default for stateful sessions. For stateless APIs (JWT-based), CSRF is typically not necessary if cookies are not used for authentication; instead use Authorization headers and CORS restrictions. Use `SameSite` cookie attributes, require anti-forgery tokens on forms, and apply CSRF tokens only to endpoints that mutate state.

### 83. CORS handling?

CORS (Cross-Origin Resource Sharing) controls browser-enforced access for cross-origin requests. Configure CORS via `CorsConfigurationSource`, controller-level `@CrossOrigin`, or at the gateway level. Permit only trusted origins, restrict methods and headers, and avoid using wildcards (`*`) in production. For credentialed requests, set `Access-Control-Allow-Credentials` carefully and ensure allowed origins are explicit.

At scale, handle CORS at the edge (API gateway/CDN) to reduce load on application servers, enforce centralized origin validation, and log blocked requests for diagnostics.

### 84. Caching in Spring?

Spring Cache abstraction provides a consistent API (`@Cacheable`, `@CacheEvict`, `@CachePut`) while allowing pluggable backends (ConcurrentMap, Ehcache, Redis). Use caching to improve read performance for expensive or frequently accessed computations. Design cache keys deterministically, set appropriate TTLs, and ensure cache invalidation aligns with data mutation patterns to avoid stale reads.

Senior considerations: prefer explicit cache boundaries, monitor hit/miss ratios, and avoid caching highly dynamic or critical consistency-sensitive data. For distributed caches use Redis or Hazelcast and consider near-cache patterns for read-heavy workloads.

### 85. Redis integration?

Redis is a versatile in-memory datastore used for caching, pub/sub, rate limiting, and session storage. Integrate with Spring via `Lettuce` or `Jedis` clients and Spring Data Redis, which provides template and repository abstractions. Use Redis for fast lookups, distributed locks (Redisson), and lightweight message passing.

At senior level, design for Redis' memory constraints: use appropriate eviction policies, data encoding (HASHes for many small objects), and avoid storing large blobs. For high availability, use Redis Sentinel or clustered Redis; prefer `Lettuce` for non-blocking and scalability benefits. Monitor memory, latency, and key cardinality.

### 86. Spring profiles?

Spring profiles (`spring.profiles.active`) enable environment-specific configuration and bean registration. Annotate beans or configuration classes with `@Profile("dev")` to restrict them to environments. Use profiles to separate dev/test/production settings, but keep the number of profiles manageable and avoid environment-specific behavior spread across code. Prefer externalized configuration with `application-{profile}.yml` files and validate production profiles in CI/CD.

### 87. Configuration properties?

Spring's `@ConfigurationProperties` binds hierarchical configuration into typed beans, enabling type-safe configuration and validation via JSR-303. Use immutable configuration properties (constructor binding) and `@Validated` to ensure correctness. Store secrets in secure stores (Vault, AWS Secrets Manager) and avoid checking secrets into VCS. For multi-service deployments, centralize common configuration in a config server or use GitOps for consistency.

### 88. Bean scopes?

Bean scopes control lifecycle: `singleton` (one per container), `prototype` (new instance per request to container), `request`/`session` (web scopes), and `application`/`websocket` in specialized contexts. Prefer singletons for stateless services; use prototype for stateful short-lived beans but manage their lifecycle yourself (container won't call destroy callbacks). For web apps, use request/session scopes carefully and avoid storing heavy state in session-scoped beans.

### 89. Prototype vs singleton?

Singleton beans are container-managed single instances used for stateless services; prototype beans cause the container to create a new instance for each injection or retrieval. Use prototype for per-use mutable state or when instances carry request-specific data, but remember the container won't manage full lifecycle (destruction). Combine with `ObjectFactory` or `Provider` to obtain fresh instances on demand.

### 90. Circular dependency?

Circular dependencies arise when two or more beans depend on each other. Constructor-based injection prevents circular dependencies (good because cycles often indicate design issues). Field/setter injection can mask cycles that the container resolves via proxies. Address cycles by refactoring responsibilities, introducing an interface/adapter, using `@Lazy` injection, or breaking the cycle with an event-driven pattern. Treat circular dependencies as a design smell.

### 91. Spring AOP?

Spring AOP provides aspect-oriented programming via proxies that intercept method calls for cross-cutting concerns (transactions, security, logging). It supports method-level advice types (`@Before`, `@AfterReturning`, `@Around`) and uses either JDK dynamic proxies (interfaces) or CGLIB proxies (classes). Use `@Aspect` for modularizing cross-cutting logic and `Pointcut` expressions to target join points precisely.

Senior usage: minimize pointcut complexity, test aspects independently, and be aware of proxy boundaries (self-invocation bypasses proxies). For performance-critical code, ensure advice logic is lightweight and avoid excessive weaving or deep pointcuts that slow initialization.

### 92. Aspects and join points?

Aspects encapsulate cross-cutting behavior; join points are well-defined points in program execution (method execution, exception handler). Pointcuts select join points, and advice contains the code applied at those join points. Use expressive pointcut design to limit scope, prefer annotation-based pointcuts for clarity, and document AOP behavior to avoid surprising interactions.

### 93. Logging strategies?

Effective logging balances sufficient context with low overhead. Use structured logging (JSON) for observability, include correlation IDs, and avoid logging sensitive data. Centralize log configuration (Logback/Log4j2), route logs to aggregators (ELK, Loki), and implement log levels consistently. For performance, avoid expensive message construction at DEBUG level (use parameterized logging) and sample high-volume logs where appropriate.

### 94. Actuator usage?

Spring Boot Actuator exposes production-ready endpoints (health, metrics, info, env) and plugs into Micrometer for metrics. Use Actuator for health checks, readiness/liveness probes, and operational insight. Secure actuator endpoints, selectively expose endpoints, and integrate with monitoring systems (Prometheus, Datadog). Customize health indicators for downstream dependencies and keep health checks fast and non-blocking.

### 95. Health checks?

Health checks (readiness and liveness) signal service availability. Liveness checks verify the process is alive; readiness checks verify dependencies (DB, caches, external services) for accepting traffic. Implement lightweight readiness checks and avoid expensive or blocking checks during startup. For container orchestration (Kubernetes), wire readiness probes to signals that reflect real readiness and use startup probes to avoid premature restarts.

### 96. Async methods?

Spring supports asynchronous execution via `@Async` and configured `TaskExecutor`s. Use async for fire-and-forget tasks, non-blocking I/O integration, and offloading long-running jobs from request threads. Tune thread pools (core/max, queue sizes, rejection policies) according to task characteristics and propagate context explicitly (security, MDC) when needed. For complex workflows prefer message-driven or reactive approaches.

### 97. Scheduling?

Use `@Scheduled` for periodic tasks and `SchedulingConfigurer` for advanced control. For distributed systems, avoid running scheduled jobs on all instances unless intentional; use leader election, Quartz clustered scheduler, or external job services. Ensure idempotency of scheduled tasks, track last-run state, and provide operational controls for enabling/disabling tasks.

### 98. WebFlux basics?

Spring WebFlux is a reactive, non-blocking web framework built on Project Reactor and supports event-loop runtimes (Netty). It embraces Reactive Streams backpressure, providing `Mono` and `Flux` types for single/multi-value async flows. WebFlux is ideal for high-concurrency, I/O-bound applications where thread-per-request is too costly.

Senior guidance: design end-to-end reactive stacks (from client to DB/driver) to avoid blocking calls, use reactive drivers (R2DBC, reactive Redis), and benchmark carefully — reactive stacks shine for high concurrency with low-latency I/O but add complexity in reasoning and debugging.

### 99. Reactive vs blocking?

Blocking (thread-per-request) is straightforward and works well when concurrency is moderate and libraries are blocking (JDBC). Reactive systems use non-blocking I/O and asynchronous composition to scale with fewer threads and better resource utilization for I/O-bound workloads. However, reactive programming increases complexity, requires compatible non-blocking drivers, and complicates debugging and observability.

Choose blocking for CPU-bound or simple services and reactive for high-concurrency I/O-bound services where infrastructure and team expertise support it. Ensure metrics, tracing, and error handling are reactive-aware.

### 100. Thread pool tuning?

Thread pool tuning balances throughput, latency, and resource usage. Identify the workload type: CPU-bound (threads ~ number of CPU cores), IO-bound (more threads to tolerate blocking), or mixed. Configure pool size, queue type (bounded vs unbounded), keep-alive times, and rejection policies. Use monitoring (thread pool metrics, queue depth, task latency) and simulate production-like loads.

For web servers tune servlet container thread pools and connection pools (DB, HTTP clients) in tandem to avoid thread starvation. Prefer bounded queues with backpressure or adaptive throttling to prevent memory growth. Document rationale for sizes and provide knobs via configuration to adjust in production.

## Section 3 — Database (Q101–Q150)

### 101. SQL joins types?

SQL joins combine rows from multiple tables based on related columns. Types: INNER JOIN (only matching rows from both), LEFT JOIN (all from left, matched from right), RIGHT JOIN (all from right, matched from left), FULL JOIN (all from both), and CROSS JOIN (Cartesian product). Self-joins compare a table to itself for hierarchical structures. Understanding join semantics avoids incorrect results and performance issues.

At scale, query planners optimize join order and execution strategy; ensure filtered predicates are pushed down before joins to minimize intermediate row counts. Use EXPLAIN plans to verify join efficiency, and prefer star schemas (normalized fact and dimension tables) in data warehouses for join optimization. For high-volume queries, consider materializing joins into denormalized fact tables or caching common joined views.

### 102. Indexing strategies?

Indexes accelerate data retrieval by maintaining sorted key structures (B-trees, hash) pointing to rows. Create indexes on columns frequently used in WHERE, JOIN, and ORDER BY clauses. Single-column indexes are simple; composite indexes on (col1, col2) can optimize multi-column filters and sorts if columns are ordered correctly for the query.

Senior considerations: indexes slow writes (INSERT/UPDATE/DELETE) due to index maintenance, so balance read gains against write costs. Use EXPLAIN to confirm queries leverage indices and detect empty scans. Monitor index fragmentation and rebuild/reorganize periodically. Avoid excessive indices — maintain a lean index set aligned to query patterns.

### 103. Clustered vs non-clustered?

A clustered index determines the physical order of table rows on disk; each table has one clustered index (typically the primary key). Non-clustered indices are separate structures pointing to data rows. In SQL Server, clustered indices store the full row; in MySQL/InnoDB, the clustered index is the primary key and non-clustered indices point to it (by primary key).

Design clustered indices for range queries and joins. Select a narrow, stable, monotonically increasing column (often surrogate key) as the clustered key. Non-clustered indices supplement for other predicates and covered queries. Understanding the underlying storage model helps optimize query plans and avoid RID/key lookups.

### 104. Query optimization?

Query optimization involves choosing the most efficient execution plan. Use EXPLAIN/ANALYZE to inspect plans, ensure indices are used, and identify full table scans. Refactor queries to push predicates early, reduce intermediate rows, and leverage available indices. Avoid OR predicates on different indexed columns (use UNION if columns have indices) and be cautious with NOT IN (use NOT EXISTS for subqueries).

Distribute expensive computations: denormalize data at write time, use materialized views, or offload complex aggregations to analytical systems. Monitor slow query logs and profile execution times to identify bottlenecks. For large tables, consider partitioning or sharding and run analytical queries on read replicas.

### 105. Execution plan?

An execution plan shows how the database engine executes a query: the operation sequence (scans, seeks, joins, aggregations), row counts, and cost estimates. EXPLAIN PLAN (Oracle), EXPLAIN (MySQL/PostgreSQL), or SET STATISTICS IO/TIME (SQL Server) reveal the strategy the optimizer chose. Plans include node costs, estimated vs actual rows (indicating cardinality estimation errors), and index usage.

Analyze plans to detect inefficiencies: full table scans on large tables, nested loops on large datasets (prefer hash or merge joins), or missing indices. Cardinality mismatches (estimated vs actual rows) suggest stale statistics or complex filter predicates. Use execution plan comparisons to validate optimization improvements.

### 106. ACID properties?

ACID guarantees data integrity: Atomicity (all-or-nothing), Consistency (valid state transitions), Isolation (concurrent transactions don't interfere), and Durability (committed changes persisted). Most relational databases implement ACID natively. NoSQL and distributed systems often weaken ACID guarantees for scale; BASE (Basically Available, Soft state, Eventually consistent) is common in distributed systems.

For mission-critical applications ensure ACID at the database layer. For high-scale, design for eventual consistency and use compensating transactions or idempotency semantics where strict ACID is unattainable. Understand your database's ACID implementation and limitations (e.g., distributed transactions are expensive).

### 107. Isolation levels?

Isolation levels control concurrent transaction visibility and phenomena prevention. READ UNCOMMITTED (dirty reads), READ COMMITTED (no dirty reads), REPEATABLE READ (no dirty/non-repeatable reads), and SERIALIZABLE (prevents phantom reads). Most databases default to READ COMMITTED balancing consistency and concurrency.

Choose based on consistency needs: REPEATABLE READ for most applications, SERIALIZABLE for critical atomic operations (stock reduces + payment). Be aware of performance costs: higher isolation levels require more locking, reducing concurrency. Use MVCC (multi-version concurrency control) databases like PostgreSQL for better isolation without locking overhead.

### 108. Deadlocks in DB?

Deadlocks occur when two transactions wait cyclically for locks. Prevent using lock ordering (always acquire locks in a consistent order), timeouts, or deadlock detection and rollback. Design transactions to be short, minimal and avoid acquiring locks in user-initiated sequences.

Detect deadlocks via logs or monitoring and analyze to identify victims. Implement retry logic with backoff for deadlock victims. For high-contention scenarios, redesign to reduce shared locks (e.g., row-level versioning, sharding by transaction ID).

### 109. Normalization vs denormalization?

Normalization (1NF, 2NF, 3NF, BCNF) reduces data redundancy and anomalies via structured dependency rules. Denormalization intentionally repeats data to optimize queries, reducing joins and improving read performance at the cost of write complexity and storage.

Most OLTP systems are normalized for consistency; OLAP/analytics lean toward denormalized star schemas for query speed. Hybrid approaches use normalized transactional databases with denormalized analytical data warehouses (ETL/ELT pipelines). Choose based on workload: normalize for frequent writes, denormalize for read-heavy analytics.

### 110. Foreign keys?

Foreign keys enforce referential integrity: a column references a primary key in another table, preventing orphaned rows. They ensure data consistency but add constraint checks on writes. Use foreign keys in OLTP systems to maintain integrity; in high-write scenarios, trade foreign keys for application-level consistency or eventual consistency via async reconciliation.

Design foreign key cascades (ON DELETE CASCADE, ON UPDATE CASCADE) carefully — unintended cascades can cause mass deletions. Archive/soft-delete patterns may work better than cascading deletes for audit trails.

### 111. Transactions?

Transactions group multiple operations into an atomic unit that either fully succeeds or fully fails. BEGIN/COMMIT/ROLLBACK control transaction boundaries. Transactions ensure ACID semantics, but extending transactions (large batches, long operations) causes lock contention.

Design short transactions targeting specific business operations. Use savepoints for partial rollbacks. Monitor transaction duration and lock waits. For distributed transactions (across multiple DBs), implement compensating transactions or saga patterns instead of expensive distributed hashes.

### 112. Stored procedures?

Stored procedures are precompiled SQL code executed on the database server. They can encapsulate business logic, improve performance (reduced network round-trips), and provide security (execution via permissions). However, they couple business logic to the database, complicate versioning, and reduce testability.

Modern practices prefer application-layer logic for testability and maintainability; use stored procedures for complex, frequently executed operations or when the database must enforce invariants. Document procedures well and version-control scripts alongside application code.

### 113. NoSQL vs SQL?

SQL databases (relational, normalized, ACID) excel at complex queries and consistency. NoSQL (key-value, document, graph, time-series) prioritizes scale, flexibility, and write performance, often relaxing consistency. SQL suits transactional workloads; NoSQL suits massive-scale, flexible-schema, or specialized data (graphs, time-series).

Many modern systems use polyglot persistence: SQL for transactional core, NoSQL for caches/logs/analytics. Choose based on data model, consistency requirements, and scale. Technology selection should drive database choice, not vice versa.

### 114. MongoDB basics?

MongoDB is a document database storing JSON-like documents in collections (like tables). Flexibility: no fixed schema, nested documents, flexible queries. Horizontal scaling via sharding. However, no joins (denormalize instead), weaker consistency, and transactions are recent additions.

Use MongoDB for rapidly evolving schemas, high-write scenarios, or when a document model fits the domain. For relational data (many-to-many, complex joins), SQL is better. Manage consistency via application logic or multi-document transactions (newer versions).

### 115. Redis use cases?

Redis is an in-memory key-value store used for caching, sessions, rate limiting, pub/sub, and leaderboards. Extremely fast for gets/sets. Use Redis where latency matters and data fits in memory.

Limitations: volatile (can lose data on restart; use persistence/replication), memory-bounded, and limited query flexibility compared to SQL. Suitable for real-time features (live counters, caches), not persistent critical state unless replicated.

### 116. Caching strategies?

Cache-aside (lazy loading): application fetches from cache, misses go to DB. Write-through: write to cache and DB. Write-behind: write to cache, async to DB (risk of loss). Cache invalidation is hard: use TTL, versioning, or event-driven invalidation. Minimize thundering herd (cache stampedes) via request coalescing or probabilistic early expiry.

Design cache keys deterministically and monitor hit ratios. Avoid caching mutable, frequently-changing data. For distributed caches (Redis, Memcached), handle partial failures gracefully.

### 117. Sharding?

Sharding horizontally partitions data across multiple database instances by a shard key (e.g., user ID mod N). Increases write capacity and query parallelism. Challenges: shard key selection (poor key causes hotspots), migration between shards, cross-shard queries (expensive), and transaction complexity.

Choose keys with even distribution and low cardinality changes. Avoid reshuffling shards; use consistent hashing or fixed schemas. Implement application-level routing or use a shard proxy/database gateway.

### 118. Replication?

Replication copies data across multiple database instances: primary (writes), replicas (reads). Improves availability and read throughput via read replicas. Consistency models vary: synchronous (strong but slow), asynchronous (fast but eventual).

Monitor replication lag carefully. Use read replicas for analytics/reporting only if eventual consistency is acceptable. For high availability, use multi-master replication (complexity) or failover automation (primary election). Test failover scenarios regularly.

### 119. Read replicas?

Read replicas are copies of the primary database accepting only reads, offloading read traffic from the primary. Useful for scaling read-heavy workloads and analytics without impacting transactional performance. Consistency is eventual (replication lag).

Design read routes carefully: route strong-consistency reads to primary, weak-consistency to replicas. Handle replica failures transparently. Monitor lag and alert on high lag to prevent stale data surprises.

### 120. CAP theorem?

CAP states a distributed system can guarantee only two of three: Consistency (all nodes see the same data), Availability (system always responds), or Partition tolerance (survives network partitions). Real systems must tolerate partitions, so they trade Consistency (CP) or Availability (AP).

CP systems (strong consistency, unavailable during partitions): suitable for critical financial/transactional data. AP systems (eventual consistency, always available): suitable for social/content systems. Design explicitly choosing your CAP trade-off and ensure the entire system (app, DB, replication) aligns.

### 121. Eventual consistency?

Eventual consistency guarantees that absent further writes, all replicas converge to the same state given sufficient time. Weaker than strong consistency but enables high availability and partition tolerance. Risk: stale reads, write conflicts (especially multi-master).

Implement conflict resolution (last-write-wins, application logic, CRDTs) for multi-master. Use version vectors or timestamps to track causality. Suitable for caches, social feeds, analytics; avoid for transactional or financial data without compensating mechanisms.

### 122. Pagination strategies?

OFFSET-based pagination (skip N, take M) is simple but slow for deep offsets (expensive skip). Keyset/cursor pagination fetches the next batch after a known record, scaling to large datasets. Use deterministic sort order and a unique identifier.

For REST APIs, expose cursors (Base64-encoded last key) or use Link headers. For UI, keyset is better for large datasets; OFFSET works for moderate result sets. Implement sort stability to avoid duplicate/missing rows.

### 123. Bulk operations?

Bulk INSERT/UPDATE operations (batch uploads) are faster than individual operations: reduced round-trips, transaction overhead, and resource utilization. Use bulk operations for ETL, imports, or daily reconciliations.

Batch sizes depend on row size and available memory; typical: 1000-10000 rows. Monitor locks and query load. For very large imports, use database-specific tools (COPY in PostgreSQL, LOAD DATA in MySQL) or parallel loading. Disable indices during bulk loads, then rebuild.

### 124. Data migration?

Data migration moves data between systems (DB upgrades, consolidation, schema evolution). Plan carefully: backward compatibility (dual-write), validation (row counts, checksums), and rollback procedures. Use dark launch patterns: run new system in parallel, validate, then cutover.

Minimize downtime: online migrations (trigger-based dual-write) are preferable to offline. Validate data integrity post-migration with automated checks. Document the migration process for repeatability.

### 125. Backup strategies?

Regular backups protect against data loss. Types: full (entire database), incremental (changes since last), and differential (changes since last full). Frequency depends on RPO (Recovery Point Objective) and RTO (Recovery Time Objective).

Test restores regularly to ensure backups work. Use off-site/cloud backups for disaster recovery. Implement automated backup verification and monitor backup duration and size. For high-availability systems, combine backups with replication for rapid recovery.

### 126. Soft delete vs hard delete?

Soft delete (mark as deleted, don't remove) preserves data for auditing and recovery. Hard delete removes rows entirely. Soft deletes enable audits and undo; hard deletes save storage and simplify queries (filter out deleted rows in all queries).

Use soft deletes for compliance/audit requirements or when undo is likely. Use hard deletes for privacy-sensitive data or when storage is a constraint. Implement both: soft delete initially, archival hard delete after a retention period.

### 127. Audit logging?

Audit logs track changes: who changed what, when, and why. Implement via triggers (DB-level), application-layer logging, or event sourcing. Logs should be immutable and queryable.

Design for compliance (GDPR, SOX, HIPAA) if required. Store in a separate, read-only system. Aggregate for analytics (who accessed what, what changed) to detect anomalies. Index heavily for audit queries.

### 128. Index performance impact?

Indices accelerate reads but slow writes (INSERT/UPDATE/DELETE must update indices). Unused indices consume space and hurt write performance. Monitor query plans and index usage; drop unused indices.

Balance: too few indices cause slow reads, too many cause slow writes and wasted space. Maintain the smallest index set supporting high-impact queries. Use covering indices (all columns needed by a query in the index) to avoid key lookups.

### 129. Composite indexes?

Composite indices on (col1, col2, col3) optimize queries filtering on col1, col1+col2, or col1+col2+col3 (left-prefix rule). Order columns by selectivity and query patterns. A composite index can eliminate joins if all needed columns are present (covering index).

Design composites carefully: the order matters for performance. Avoid over-indexing — review query patterns and avoid redundant composites.

### 130. Optimistic vs pessimistic locking?

Optimistic locking assumes conflicts are rare; uses version columns or timestamps to detect conflicts on write. Pessimistic locking acquires locks upfront before reading (SELECT FOR UPDATE). Optimistic suits low-contention scenarios and distributed systems; pessimistic suits high contention and ensures immediate consistency.

Choose based on workload characteristics. Implement optimistic with retry logic; pessimistic requires careful lock ordering to avoid deadlocks. Most Web/mobile apps use optimistic locking for better concurrency.

### 131. REST best practices?

Design REST APIs around resources (nouns), not actions (verbs). Use HTTP methods meaningfully: GET (safe, idempotent), POST (create), PUT (replace), PATCH (partial update), DELETE (remove). Status codes convey results: 200 (OK), 201 (Created), 204 (No Content), 400 (Bad Request), 401 (Unauthorized), 403 (Forbidden), 404 (Not Found), 500 (Server Error).

Version APIs (Accept header, URL path, or query param) and maintain backward compatibility. Implement pagination, filtering, sorting server-side. Use HAL/JSON:API for hypermedia. Document with OpenAPI/Swagger. Rate limit and throttle. Test with curl/Postman or automated suites.

### 132. Idempotent APIs?

Idempotent operations return the same result if executed multiple times (GET, PUT, DELETE are idempotent; POST is not). For safety, POST should be idempotent via idempotency keys: client sends a unique key, server de-duplicates retries.

Implement server-side idempotency stores (in-memory, Redis) keying on (client_id, idempotency_key) mapping to the response. Timeout/evict old entries. Critical for payment, booking, and state-changing operations where retries can occur due to network failures.

### 133. API versioning?

Multiple strategies: URL path (`/v1/users`), Accept header (`Accept: application/vnd.api+json; version=1`), query parameter (`?api-version=1`). URL path is explicit and SEO-friendly; headers are simpler operationally.

Plan for evolution: add optional fields (no breaking), deprecate old endpoints gradually, coordinate with clients. Semantic versioning (major.minor.patch) signals compatibility. Support multiple versions simultaneously during transition to avoid forced client upgrades.

### 134. Rate limiting?

Rate limiting restricts request frequency per client to prevent abuse and ensure fair resource allocation. Algorithms: token bucket (fixed rate, burst allowance), leaky bucket (smooth rate), sliding window (precise but stateful).

Implement at API gateway or application layer. Store limits in distributed store (Redis) for multi-server consistency. Return 429 (Too Many Requests) with Retry-After headers. Vary limits by tier (free, premium) and endpoint sensitivity. Monitor and alert on high-rate clients.

### 135. API gateway?

API gateways sit between clients and microservices, handling cross-cutting concerns: authentication, rate limiting, request routing, transformation, caching, and logging. Popular: Kong, AWS API Gateway, nginx, Spring Cloud Gateway.

Gateways reduce coupling and enable traffic shaping. Use them for versioning, request validation, response transformation, and service discovery. However, they're another component to operate; minimize custom logic in the gateway. For microservices, gateways are essential for unified entry points and common policies.

### 136. Microservice communication?

Direct service-to-service calls (REST, gRPC) are synchronous and simple but couple services and require resilience patterns (retries, timeouts, circuit breakers). Async messaging (event bus, message queue) decouples services but adds complexity (eventual consistency, ordering).

Design based on coupling tolerance and consistency needs. Prefer async for non-time-critical operations (email, notifications); sync for user-facing reads. Use service mesh (Istio) for transparent resilience and observability without client code changes.

### 137. Circuit breaker?

Circuit breakers prevent cascading failures by stopping requests to a failing service and returning errors/defaults instead. States: Closed (normal, request passes), Open (failing, request fails immediately), Half-Open (testing recovery, allowing probe requests).

Tune thresholds (failure rate, count) and timeouts to reflect recovery times. Pair with retries, timeouts, and fallbacks. Libraries: Resilience4j, Hystrix. Monitor circuit state and alert on frequent opens to catch issues early.

### 138. Resilience4j?

Resilience4j is a lightweight library providing resilience patterns: circuit breakers, retries, timeouts, bulkheads, and rate limiters. It's event-driven, composable, and has low overhead.

Use circuit breakers for external calls, retries with exponential backoff for transient failures, timeouts to prevent hanging threads, bulkheads to isolate resources, and rate limiters to control load. Integrate with Spring for decorators on methods or explicit use via APIs. Monitor metrics and logs for circuit state, retry counts, and timeouts.

### 139. Message queues?

Message queues decouple producers and consumers: producers send messages, queues persist them, consumers process asynchronously. Benefits: decoupling, scalability, and resilience. Drawbacks: eventual consistency, debugging complexity, and operational overhead.

Popular: RabbitMQ (AMQP), Apache Kafka (event streaming), AWS SQS, Google Cloud Pub/Sub. Choose based on throughput, message ordering, durability, and consumer patterns. Implement at-least-once delivery guarantees and idempotent consumers. Monitor queue depth and consumer lag.

### 140. Kafka basics?

Kafka is a distributed event streaming platform: producers publish records to topics (sharded into partitions), consumers read sequentially from partitions. Scales to millions of events/sec with low latency.

Partition key determines placement; messages in a partition are ordered. Consumer groups enable parallel consumption. Kafka retains messages (logs), enabling replay. Use for event sourcing, streaming analytics, and high-volume data pipelines. Operational complexity is higher; ensure monitoring, backup, and capacity planning.

### 141. Event-driven architecture?

Event-driven systems emit domain events (DomainEvent objects, JSON messages) capturing state changes. Services subscribe to event streams, triggering reactions (notifications, data syncs). Enables loose coupling and scalability.

Implement event publishing (application code, database triggers, log-based CDC), event bus (message queue, event store), and event subscribers. Ensure idempotency (by event ID), order (per aggregate), and retention (audit trail). Event versioning handles schema evolution. Complexity: eventual consistency, debugging distributed flows, testing.

### 142. Saga pattern?

Sagas coordinate multi-service transactions without distributed commits. Orchestration: a central service directs steps (e.g., payment service charges, inventory service reserves). Choreography: services publish events and react to others' events.

Implement compensating transactions for rollback (reverse charges if reservation fails). Sagas tolerate temporary inconsistency and partial failures better than 2-phase commits. Design idempotent service calls and careful event ordering.

### 143. Distributed transactions?

Distributed transactions across multiple services are expensive and fragile. Two-phase commit (2PC) blocks participants during voting, vulnerable to failures. Avoid in high-latency environments.

Prefer eventual consistency via sagas, event-driven patterns, or accept eventual inconsistency. If strict ACID is necessary, keep transactions local (single service). Design for single-version truth: one service owns a data model, others replicate.

### 144. Service discovery?

Service discovery automatically locates service instances (IP, port) enabling dynamic routing without hardcoded addresses. Pull-based: clients query a registry (Eureka, Consul); push-based: registry notifies clients.

Use with load balancers for traffic distribution. Important for container/cloud deployments where instances are ephemeral. Implement health checks ensuring registered instances are healthy. Coordinate with service mesh for transparent discovery and resilience.

### 145. Config server?

Config servers (Spring Cloud Config, Consul, etcd) centralize configuration enabling dynamic updates without redeployment. Clients pull or subscribe to config changes.

Store sensitive configs (secrets) in secure stores (Vault) separate from code. Version config alongside app code for traceability. Use profiles (dev, prod) to vary settings per environment. Implement config refresh strategies (poll, webhook) and test configuration changes in staging.

### 146. Load balancing?

Load balancers distribute traffic across multiple servers optimizing resource utilization and availability. Algorithms: round-robin (sequential), least connections (lowest active), IP hash (sticky sessions), weighted (server capacity).

Deploy at different layers: HTTP (Layer 7) for URL-based routing, TCP (Layer 4) for protocol-agnostic balancing. Use health checks ensuring live backends. For microservices, leverage client-side load balancing (Ribbon, Spring Cloud LoadBalancer) or service mesh.

### 147. Blue-green deployment?

Blue-green deployment runs two identical production environments: blue (current), green (new). Cut traffic after validating green, enabling fast rollback if issues arise.

Requires load balancer switchover and stable databases (shared or replicated). Zero-downtime deployments and rapid rollbacks are benefits. Operational cost: running dual environments. Coordinate with CI/CD pipelines to automate validation and switchover.

### 148. Backend performance tuning?

Performance tuning involves identifying bottlenecks and optimizing. Profile CPU, memory, I/O using APMs (Datadog, New Relic), JVM profilers (YourKit, JProfiler), and database slow logs. Common bottlenecks: slow queries, GC pauses, blocked threads, inefficient algorithms.

Optimize incrementally: measure before/after to confirm improvements. Focus on high-impact items (hottest code paths). Use caching, batch operations, connection pooling, and async processing. Keep performance regressions from creeping in via continuous monitoring and load testing.

### 149. Distributed Systems Overview

Distributed systems span multiple machines and require handling: partial failures, latency, eventual consistency, and operational complexity. CAP theorem guides consistency trade-offs. Design for fault tolerance via redundancy, health checking, and automated failover.

Plan for the human element: operational runbooks, incident response playbooks, and on-call rotations. Test failure scenarios (chaos engineering). Monitor deeply (metrics, logs, traces) to enable rapid diagnosis. Scale horizontally (multiple servers) rather than vertically (larger machines) for resilience and cost-effectiveness.

### 150. High Availability Architecture

High availability (HA) systems tolerate component failures and maintain service. Patterns: redundancy (N+1 servers), load balancing (distribute traffic), health monitoring (detect failures), automated failover (elect new leader if primary fails), and coordination (ZooKeeper, etcd).

Design for graceful degradation: shed non-critical features under load to maintain core functionality. Use RTO (Recovery Time Objective) and RPO (Recovery Point Objective) to guide redundancy and backup strategies. Test failover regularly. For critical systems, multi-region replication and disaster recovery procedures are essential. Document runbooks for common failure scenarios.

## Section 4 — React / Frontend (Q151–Q200)

### 151. Virtual DOM?

The Virtual DOM is React's in-memory representation of the UI (a lightweight JavaScript object tree mirroring the DOM). React renders components to vDOM, compares (diffs) the new vDOM with the previous one, determines minimal updates, and reconciles those changes to the real DOM. This abstraction decouples rendering logic from direct DOM manipulation and enables efficient batching of updates.

Benefits: abstracts browser differences, improves performance via diffing/batching, and enables advanced features (SSR, native rendering). The cost: vDOM creation and diffing logic. For most apps, vDOM overhead is negligible compared to DOM operations. Understanding reconciliation prevents subtle bugs (key selection, conditional mounting).

### 152. Reconciliation?

Reconciliation is React's algorithm for updating the UI when state/props change. React diffing: if elements have different types (div vs span), rebuild; if same type, preserve the DOM node and diff attributes/children. Keys help identify elements across re-renders, essential for lists (without keys, React may re-render unrelated items).

Reconciliation is heuristic-based (O(n), not optimal), suitable for most UIs. Understand key selection: stable, unique identifiers (IDs), not indices. Poor keys cause re-mounts, losing component state and refs. This is a common source of subtle bugs in React apps.

### 153. React lifecycle?

Class component lifecycle phases: mounting (constructor, render, componentDidMount), updating (render, componentDidUpdate on prop/state change), and unmounting (componentWillUnmount). Hooks replicate lifecycle via useEffect dependencies and cleanup functions.

Lifecycle is essential for managing side effects (API calls, subscriptions), animations, and cleanup. Mismanagement (missing cleanup, wrong dependencies) causes memory leaks and unwanted re-renders. Prefer functional components with hooks; lifecycle is simpler and more composable with hooks.

### 154. Hooks rules?

Rules of Hooks (enforced by ESLint): only call hooks at the top level of components/custom hooks (not conditionally or in loops), and only in React functions, not regular JS. Violations break React's ability to track hook state per component.

These rules enforce a consistent call order enabling React to map hook state to functional closures. Violators cause "rules of hooks" linting errors. Use custom hooks to encapsulate stateful logic and compose behaviors safely.

### 155. useState batching?

React batches state updates in event handlers (click, input) and lifecycle methods, applying all updates in a single render to improve performance. Outside these contexts (promises, timeouts, certain events), updates may not batch (React 18 introduces automatic batching in more scenarios).

Batching reduces re-renders but can surprise developers expecting immediate state updates. For imperative updates or when immediate reads are needed, use flushSync() (React 18+). Understanding batching avoids state update surprises.

### 156. useEffect lifecycle?

useEffect runs side-effect logic after component renders and handles cleanup. Dependencies array controls when the effect re-runs: empty = once on mount, [deps] = when deps change, omitted = every render. Return a cleanup function to undo side effects (unsubscribe, cancel timers).

Common pitfall: forgetting cleanup causes memory leaks (subscriptions leaking, timers persisting). Incorrect dependencies cause stale closures and ineffective logic. Use React DevTools Profiler to detect unnecessary effect runs. For complex effects, consider useReducer or custom hooks.

### 157. useMemo vs useCallback?

useMemo memoizes computations: `useMemo(() => expensiveCalc(a, b), [a, b])` caches results if deps unchanged. useCallback memoizes function references: `useCallback(() => handleClick(), [deps])` ensures stable function identity across renders.

Use when passing to memoized children (prevent unnecessary re-renders) or as dep for other hooks. Overuse adds overhead (dependency tracking, memory for cached values). Profile before optimizing; often unnecessary. Both are tools to optimize after identifying real performance bottlenecks via React Profiler.

### 158. useRef usage?

useRef creates a mutable reference persisting across renders without triggering re-renders: `const inputRef = useRef(null); inputRef.current.focus()`. Use for direct DOM access (input focus, measuring, playing video), stable timers, or storing mutable values decoupled from render.

Abuse (storing derived state in useRef) leads to inconsistent UIs. Refs are escape hatches; prefer declarative state and props when possible. Use refs for truly imperative needs (canvas, audio, unmeasurable values).

### 159. Custom hooks?

Custom hooks are JavaScript functions starting with "use" that call built-in hooks, extracting reusable stateful logic. Example: `useFormInput` encapsulates input state and handlers. Hooks compose: a custom hook can call other hooks.

Custom hooks improve reusability, testability, and separation of concerns. Test them like pure functions (inputs → outputs). Share hooks across projects via packages for maximum reuse. Keep custom hooks simple and composable; complex logic belongs in custom hooks, not components.

### 160. Controlled components?

Controlled components manage form input state in React state, making the UI state source of truth. Uncontrolled components store state in the DOM (ref-based).

Controlled components enable instant validation, conditional submission, and integration with application state. Uncontrolled components are simpler for simple forms without validation. For most modern apps, controlled components are standard; libraries (Formik, React Hook Form) ease management of many inputs.

### 161. Context API?

Context enables passing data deeply through component trees without prop-drilling. Create context (`React.createContext`), provide a value at a parent, and consume via `useContext(Context)`. Avoids passing props through intermediate components.

Overuse of Context couples far-apart components and makes data flow implicit. Each context change causes all consumers to re-render (no granular subscription). For larger state, prefer Redux or local state management. Context works well for global concerns (theme, language, auth).

### 162. Redux architecture?

Redux is a predictable state container: single immutable state tree, actions describe changes, reducers compute new state from old state + action, and a store coordinates everything. Middleware (Redux Thunk, Redux Saga) handles async logic.

Benefits: predictable state mutations, time-travel debugging, testability. Drawbacks: boilerplate, learning curve, overkill for simple apps. Modern alternatives (Context + Hooks, Zustand, Jotai) offer lighter state management. Use Redux when the app is complex and benefits from centralized, predictable state.

### 163. Redux Toolkit?

Redux Toolkit simplifies Redux: `createSlice` bundles actions + reducer + selectors; `createAsyncThunk` handles async data; `configureStore` sets up middleware and DevTools. Reduces boilerplate significantly.

Modern Redux development uses Toolkit; it's the recommended way. Immer integration enables "mutative" reducer syntax that's actually immutable under the hood. Learn Redux Toolkit for Redux applications.

### 164. Middleware?

Middleware in Redux intercepts actions before reducers, enabling async operations, logging, or action transformation. Redux Thunk dispatches async action creators returning functions; Redux Saga uses generator functions for complex async flows and cancellation.

Middleware is powerful but adds complexity. For simple apps, consider simpler alternatives (useEffect for side effects, local state). Test middleware separately from components. Compose middleware for reusability.

### 165. Async flow?

Handling async data (API calls, timers) requires coordinating state changes before/after operations. Redux Thunk: dispatch a function that fetches data, dispatches loading/success/error actions. Redux Saga: watchers listen for actions, fork side effects (fetch), handle results.

Modern approaches: React Query/SWR manage server state separately from app state, simplifying async data handling. useEffect for simple cases. Understand data fetching patterns (requests, caching, error handling) and choose the tool fitting your scale.

### 166. React Query?

React Query manages server state (API data, caching, synchronization). Replace Redux for server state with hooks like `useQuery`, `useMutation`. Built-in caching, refetching, deduplication, and background updates reduce boilerplate significantly.

Benefits: separation of client vs server state, automatic refetch on focus/mount, optimistic updates, pagination support. Pairs well with Redux (client state) or local state. Reduces async complexity in most apps. Consider React Query first for data fetching before Redux.

### 167. Server vs client state?

Server state (API data, DB records) is owned by the server; client state is local (form values, UI flags, selections). Mixing them causes sync issues. React Query / SWR manage server state (fetch, cache, sync); useState/Redux manage client state.

Design clear boundaries: server state lives in React Query/cache, client state in React state/context. Avoid duplicating server state in Redux (causes staleness). This separation simplifies reasoning and updates.

### 168. Performance optimization?

React optimizations: memoize components (React.memo), lazy-load with code splitting, virtualize long lists, defer non-critical updates (useTransition). Profile with React DevTools Profiler to identify slow renders or unnecessary re-renders.

Common bottlenecks: re-rendering children (use keys, memo), expensive computations (useMemo), N+1 queries (batch requests), large bundles (code split, tree-shake). Avoid premature optimization; measure first. Most React apps are fast enough with proper patterns (memoization, virtualization, code splitting).

### 169. Memoization?

Memoization caches results of expensive computations. In React: React.memo memoizes components, useMemo caches values, useCallback caches functions. Benefits: skip re-renders/recalculations if inputs unchanged.

Downsides: memory for cached values, dependency tracking overhead, potential bugs if deps are wrong. Profile before memoizing. Often premature optimization. Use when profiling shows bottlenecks or passing to memoized children.

### 170. Prevent re-renders?

Use React.memo for components unchanged unless props change. useMemo for expensive child props. useCallback for stable callbacks. Keys for list items to prevent unrelated items re-rendering. Context selectors (custom hooks) to subscribe only to relevant state.

Over-memoizing complicates code. Focus on structural optimizations (components, keys, state locality) before micro-optimizations. Profile to verify improvements.

### 171. Code splitting?

Code splitting breaks bundles into chunks loaded on-demand, reducing initial load. Use `React.lazy` + `Suspense` for route-based splitting (each route is a chunk). Tool-level: webpack automatically splits by async imports.

Benefits: faster initial page load, lazy evaluation of code. Drawbacks: complexity, potential waterfall loads. For most SPAs: split at route boundaries. For components, split heavy libs (editors, charts) as needed.

### 172. Lazy loading?

Lazy loading of components/images defers loading until needed. `React.lazy` for dynamic imports; `Suspense` shows fallback. Images: `IntersectionObserver` or library (react-lazyload, react-intersection-observer) to load when visible.

Benefits: faster initial load, reduced bandwidth. Drawbacks: complexity, potential "blank" states. Use at route and heavy component boundaries. For list virtualization, lazy-loading images in viewports is essential.

### 173. Suspense?

Suspense is React's mechanism for handling async operations in a declarative way. Wrap lazy components/async code with `<Suspense fallback={<Loader/>}>`. When suspended (loading), fallback renders; when ready, component renders.

Suspense simplifies async handling but is relatively new and not mature for general data fetching (use React Query instead). For data fetching, libraries wrap Suspense usage. Expect Suspense to evolve as React Concurrent features stabilize.

### 174. Error boundaries?

Error boundaries catch JavaScript errors in child components and display fallbacks (error UI, logs). Implemented as class components with `componentDidCatch` or `getDerivedStateFromError`.

Use to gracefully handle errors (render fallback instead of crashing). Don't catch event handler errors (use try/catch), async errors (React 16 limitation), or server-side errors. Combine with error reporting services (Sentry) to track production errors.

### 175. React concurrent rendering?

React Concurrent features enable non-blocking rendering: the main thread isn't blocked during large renders. useTransition marks non-urgent updates (can be interrupted if higher-priority work arrives). useDeferredValue defers a value update for lighter re-renders.

Benefits: faster interactions despite heavy renders. Downsides: complex mental model, potential inconsistency between renders if refs access state mid-render. Experimental; use when profiling shows main-thread blocking from renders.

### 176. Transition API?

useTransition marks updates as non-urgent transitions that don't block the UI. `startTransition(() => setState(...))` marks the update as a transition, allowing interruption by urgent updates (user input).

Use for search filtering, pagination, or expensive re-renders. Benefits: responsive UI despite heavy computations. Requires understanding concurrent rendering; use profiling to validate improvements.

### 177. useDeferredValue?

useDeferredValue defers updating a value "later", allowing higher-priority updates to interrupt. Useful for keeping rendered content fresh while deferring expensive operations on updated data.

Similar to useTransition but for values instead of imperative updates. Use for lists with expensive filtering/sorting deferred while UI stays responsive. Concurrent feature; validate improvement via profiling.

### 178. Component design patterns?

Patterns: Container (logic, state) + Presentational (UI only) for separation, Render Props (function as child for state sharing), Higher-Order Components (HOC, wrap for behavior addition), Custom Hooks (modern composition). Compound components expose sub-components for flexible composition.

Modern React favors Hooks + functional components. Render Props and HOCs are older patterns now replaced by Hooks for simplicity. Compound components remain useful for flexible libraries (Headless UI).

### 179. Compound components?

Compound components expose sub-components sharing implicit state (context): `<Select><Select.Option value="1"/></Select>`. Sub-components access parent state via context. Enables flexible composition while centralizing logic.

Benefits: intuitive API, flexible composition. Use for libraries/component groups. Popular in Headless UI and design systems.

### 180. HOC vs hooks?

Higher-Order Components (HOCs) wrap a component to add behavior. Custom Hooks extract stateful logic for reuse. Hooks are preferred: simpler, fewer performance pitfalls (no wrapper hell), easier reasoning.

HOCs remain useful for libraries needing deep component control (Redux connect), but Hooks (useConnect or hooks API) are more modern. Migrate away from HOCs when possible.

### 181. Render props?

Render Props is a pattern where a component accepts a function prop that returns JSX. `<DataFetcher render={data => <Child data={data}/>}/>`. Enables state sharing without HOC wrapper hell.

Hooks replaced Render Props for most use cases. Render Props remain useful in some library contexts but are less common now.

### 182. Form handling?

Options: controlled components (setState per input), Formik, React Hook Form, or useReducer for complex forms. Controlled forms integrate easily with React; they require validation, submission, and error handling.

React Hook Form is lightweight and performant (minimal re-renders); Formik is feature-rich (validation, async). Choose based on complexity. For custom forms, controlled components suffice. For large forms, use a library.

### 183. Validation libraries?

Libraries: Formik (validation + form state), React Hook Form (lightweight, hook-based), Yup/Zod (schema validation). Client-side validation improves UX; always validate server-side for security.

Combine libraries: React Hook Form + Zod for lightweight, type-safe validation. Or custom validation logic for simple apps. Validate on blur/submit depending on UX goals.

### 184. Accessibility?

Accessibility (a11y) ensures apps work for users with disabilities. Semantic HTML (button instead of div), ARIA labels, keyboard navigation, sufficient color contrast, and screen reader support. Use tools: axe, Lighthouse, WAVE.

React apps often break a11y by misusing divs, ignoring focus management, or skipping labels. Treat a11y as first-class. Test with screen readers (NVDA, JAWS). Many a11y issues are cheap to fix if caught early.

### 185. ARIA?

ARIA (Accessible Rich Internet Applications) adds semantic metadata via attributes (role, aria-label, aria-hidden) helping assistive tech understand dynamic content. Use when semantic HTML isn't sufficient.

Don't overuse ARIA; prefer semantic HTML (button, nav, section). Use aria-live for dynamic updates, aria-expanded for toggles, aria-label for icon buttons. Validate ARIA via axe or similar tools.

### 186. CSS architecture?

CSS approaches: BEM (Block-Element-Modifier) for scalable class naming, CSS Modules (scoped styles), CSS-in-JS (styled-components, emotion), or utility-first (Tailwind). Each trades-off between reusability, performance, and DX.

For large projects, scoped (CSS Modules, CSS-in-JS) prevents name conflicts. Utility-first (Tailwind) reduces custom CSS but increases HTML class counts. Choose based on team preference and project size. Consistency matters more than the choice.

### 187. Styled components?

Styled Components is a CSS-in-JS library using template literals: `const Button = styled.button\`color: blue;\`;`. Benefits: scoped styles, dynamic styling via props, no class name conflicts.

Drawbacks: runtime overhead, bundle size (can be mitigated via Babel plugin), potential performance if overused. SSR requires careful setup. Good for component libraries and dynamic themes. For simpler apps, CSS Modules or Tailwind may suffice.

### 188. Tailwind?

Tailwind is a utility-first CSS framework: apply utility classes (flex, text-lg, bg-blue-500) instead of writing CSS. Large class names on elements but reduced custom CSS.

Benefits: consistency via design tokens, rapid prototyping, no unused CSS (purging). Drawbacks: verbose HTML, learning curve, slower than hand-written CSS. Popular for rapid development. Prefer for new projects; retrofitting to existing CSS is tedious.

### 189. Microfrontend?

Microfrontends decompose UI into independently deployable mini-applications sharing a shell/container. Module Federation (webpack 5) enables this. Benefits: independent releases, team/tech autonomy. Drawbacks: complexity, shared state/styling challenges, duplicated deps.

Use for large orgs with multiple teams. Smaller projects should start monolithic, refactor to microfrontends if scaling demands warrant. Coordinate carefully: shared APIs, styling, routing, and state management.

### 190. Module federation?

Module Federation (webpack 5+) enables dynamic loading of remote modules at runtime. One app exposes modules; others consume them. Enables true microfrontends.

Setup: webpack config with federationPlugin, shared dependencies. Runtime dynamic loading. Complex but powerful for scaling large multi-team projects. Requires discipline in versioning, testing, and API stability.

### 191. Testing React?

Test frameworks: Jest (unit), React Testing Library (component semantics), Cypress/Playwright (e2e). Focus on user interactions, not implementation. Test-first development (TDD) or test alongside development.

Key: test behaviors, not internals. Query by role/label (user-facing), not by test IDs (fragile). Mock APIs, not components. Achieve good coverage (critical paths, edge cases) without chasing 100%.

### 192. Jest?

Jest is a unit testing framework with snapshot testing, mocking, and built-in assertions. Run with `npm test`. Mock modules, timers, and APIs. Snapshots capture output for regression detection (use carefully, review diffs).

Jest pairs with React Testing Library for component testing. Strong matchers, fast, good DX. Standard for React projects.

### 193. React Testing Library?

React Testing Library focuses on testing components as users interact, not internals. Queries: getBy (throws), queryBy (null), findBy (async). Never test implementation details (state, refs).

Encourage good practices (accessible queries, user-perspective testing). Pairs perfectly with Jest. Learn to avoid testing Library shortcuts and anti-patterns (waitFor, within overuse).

### 194. Snapshot testing?

Snapshots capture rendered output and flag diffs in future runs. Useful for catching regressions in large component outputs. Warning: snapshots rot if not maintained. Review snapshot diffs carefully; don't blindly accept changes.

Use snapshots sparingly (large outputs, stable UIs). Prefer specific assertions (text content, attributes) for clarity. Snapshot tests catch changes, not correctness.

### 195. Mocking APIs?

Mock APIs in tests using libraries: MSW (Mock Service Worker, intercepting fetch/XHR), jest.mock, or API client mocking. MSW is powerful (network-level mocking) and decouples test setup from implementation.

Mock at the right level: API mocking (MSW) tests real API integration; jest.mock tests component logic in isolation. Combined approach balances coverage and test speed.

### 196. Performance profiling?

React DevTools Profiler measures render times, re-render causes, and component interactions. Chrome DevTools tracks Network, Performance (main thread), and Memory. Tools: Lighthouse (audit), WebPageTest (detailed).

Profile real user loads, not dev server. Identify bottlenecks: slow renders, large bundles, network waterfalls. Prioritize high-impact fixes. Continuous monitoring catches regressions.

### 197. React DevTools?

React DevTools browser extension enables component tree inspection, props/state viewing, and Profiler. Essential for debugging. View which hooks are in a component, inspect context values, track re-renders.

Master React DevTools for efficient debugging. Pair with browser DevTools for network, performance, and memory insights.

### 198. State normalization?

State normalization flattens nested structures, storing data by ID to avoid duplication and simplify updates. `{ users: { 1: {name: "John"}, 2: {...} } }` vs nested `{ users: [{id: 1, name: "John"}] }`.

Benefits: avoid updating deep nests, prevent stale duplicates. Drawbacks: denormalization required for display, boilerplate. Use for large, complex state. Redux (reselect library) and Entity adapters help. ORM-like libraries (Reselect, Immer) ease normalized updates.

### 199. Virtualization lists?

Virtualization renders only visible list items (+ buffer), drastically reducing DOM nodes for huge lists. Libraries: react-window, react-virtualized. Enables smooth scrolling through millions of items.

Essential for performance with large lists. Fixed item height simplifies virtualization; variable heights require measuring. Test scrolling smoothness and edge cases (rapid scrolling, item addition/removal).

### 200. Large data rendering?

Strategies: virtualization (visible items), pagination (page-by-page), lazy loading (as you scroll), or aggregation (roll up in backend). Combine with filtering/search for manageability.

Choose based on data characteristics and UX requirements. Most users prefer pagination or infinite scroll over full-page loads. Virtualization suits static lists; pagination suits navigable datasets. Backend aggregation is preferred when feasible.

## Section 5 — Real-Time Systems / WebSockets (Q201–Q250)

### 201. How WebSockets work?

WebSocket is a full-duplex communication protocol over TCP enabling persistent bidirectional connections. Client initiates HTTP upgrade, server accepts, and both can send messages anytime (no request/response cycle like HTTP). Browsers expose via WebSocket API: `new WebSocket('ws://host')`. Messages are frames with type (text, binary) controlling encoding.

Use WebSockets for low-latency, server-initiated updates (chat, live feeds, collaborative editing, multiplayer games). HTTP polling is inefficient (frequent requests); Server-Sent Events work for one-way server-to-client streams. WebSockets handle bidirectional, real-time scenarios. Plan for connection state, reconnection, and message ordering at scale.

### 202. HTTP vs WebSocket?

HTTP is request-response: client initiates, server responds, connection closes. Stateless, cacheable, scalable via stateless servers. WebSocket is persistent connection: either side sends data, low-latency, stateful (server tracks connections).

Use HTTP for simple req/resp (APIs, static content). Use WebSocket for low-latency bidirectional (chat, gaming, live updates). Hybrid: REST for state mutation, WebSocket for notifications/live data.

### 203. Handshake process?

WebSocket handshake: client sends HTTP Upgrade request with Sec-WebSocket-Key header; server responds 101 Switching Protocols with Sec-WebSocket-Accept (derived from key). Protocol switches to WebSocket. Both parties can now send frames.

Handshake is HTTP-compatible (proxies, firewalls allow), then binary framing takes over. Understanding the handshake helps troubleshoot connection issues (CORS, header mismatches).

### 204. Scaling WebSockets?

Single server handles thousands of connections (event-loop runtime: Node, Netty). Beyond single server, challenges: distributing connections, delivering messages across servers, and maintaining state.

Strategies: load balance connections (sticky sessions via IP hash or session affinity), use message broker (Redis Pub/Sub, Kafka) for cross-server messaging, and store session data in distributed store (Redis). Horizontal scaling requires careful routing and messaging patterns.

### 205. Sticky sessions?

Sticky sessions route all requests from a client to the same server (enabled by IP hash or session cookie). Necessary for stateful connections (WebSockets) without distributed state.

Downside: server failure loses client session; rebalancing during scaling is complex. For true horizontal scaling, decouple state into a distributed store and use load balancers without stickiness.

### 206. Message ordering?

WebSocket message order is guaranteed within a single connection (TCP guarantees). For multiple producers/servers sending to a single client, messages may interleave or arrive out of order.

Implement message sequencing: client tracks received sequence numbers, reorders if needed. Server publishes to a message queue ensuring ordered delivery. Design carefully for ordering requirements (critical for state consistency).

### 207. Reconnection strategies?

Clients should handle disconnections (network loss, server restart) and reconnect automatically. Strategies: exponential backoff (1s, 2s, 4s, ..., max 30s) to avoid overwhelming servers, jitter (randomize backoff) to prevent thundering herd, and connection timeouts to detect dead connections.

Implement with client libraries (Socket.io, SockJS) that handle reconnection logic. Server should persist undelivered messages (queues) or resync state on reconnect. Design for resilience and eventual consistency during brief disconnections.

### 208. Heartbeats?

Heartbeats (keep-alives) are periodic messages (ping/pong or app-level) sent from server to client (or both) to detect stale connections. WebSocket protocol has built-in ping/pong frames; apps can implement custom heartbeats.

Set interval appropriately (30-60s) to balance overhead and detection speed. Detects broken connections (network disconnect, crashed peer). Many proxies close idle connections; heartbeats prevent this. Pair with timeouts: if pong not received, connection is dead.

### 209. Pub/Sub systems?

Pub/Sub (publish-subscribe) decouples message senders (publishers) from receivers (subscribers). Publishers emit events to topics; subscribers registered to topics receive them. Enables N-to-M communication patterns.

Redis Pub/Sub, Kafka, RabbitMQ, and cloud services (AWS SNS/SQS, GCP Pub/Sub) implement Pub/Sub. Benefits: decoupling, scalability. Drawbacks: eventual delivery (Kafka/durable), no persistence (Redis), added complexity. Critical for event-driven architecture.

### 210. Redis pub/sub?

Redis Pub/Sub sends messages to subscribers in real-time but doesn't persist. Publishers publish to channels; subscribers receive immediately. Simple, low-latency, high throughput.

Limitation: no message history (subscribers miss messages published before subscription). Use for real-time notifications (live feeds). For durability and replay, use Kafka instead.

### 211. Kafka vs WebSocket?

Kafka is a distributed event log (persistent messages, partitions, consumer groups). WebSocket is a bidirectional network connection (for real-time messages, low-latency). Kafka survives consumer downtime, supports replay, scales to massive throughput. WebSocket is immediate, point-to-point, suitable for live interaction.

Combine: WebSocket for live client interaction, Kafka for robust server-side event processing and durability.

### 212. Load balancing sockets?

Load balance WebSocket connections via Layer 4 (TCP/IP) hash (client IP, port -> server) or Layer 7 (HTTP, custom logic). Sticky routing ensures reconnects go to the same server (without distributed state).

For true scaling, add a message broker (Redis, Kafka) and decouple socket handling from app logic. Clients connect to any server; servers route messages via broker. Eliminates sticky requirement and enables zero-downtime deployments.

### 213. Message queues? (Webocket context)

Client-side message queues buffer outgoing messages during connectivity loss, sending on reconnect. Server-side queues store messages for offline clients, delivery on next connect.

Implement for reliability: clients queue messages, retry failures, acknowledge delivery. Servers queue undelivered messages, limited by TTL/size. Pair with unique client IDs and idempotent consumption.

### 214. Latency optimization?

Minimize latency in real-time systems: close geographic proximity (CDN, regional servers), efficient serialization (binary, protobuf, not JSON), batching (collect messages, send together), and avoid blocking operations.

Monitor end-to-end latency (client timestamp, server echo, client measure). Profile bottlenecks: network, serialization, server processing. For gaming/trading, sub-100ms is critical; for chat, sub-second is acceptable. Design for use case requirements.

### 215. Real-time architecture?

Real-time systems combine WebSockets (low-latency) with message queues (durability), caches (speed), and event streams (replay/analytics). Typical flow: client connects via WebSocket, sends/receives messages, broker persists for reliability, other services consume events.

Design for resilience: degrade gracefully on connection loss, handle order-of-arrival, implement deduplication. Monitor latency, message volume, and connection health. Use load balancers and distributed state to scale horizontally.

### 216. Chat system design?

Components: WebSocket server (connection management), message store (durability), user service (auth, profiles), read receipts (who's online), presence (typing indicators). Users connect, send messages (broadcast to recipients), store in DB. Online users receive immediately; offline users retrieve on next login.

Scale: partition messages by room/channel, use Redis for online presence/typing indicators, Kafka for durability, multiple WebSocket servers behind load balancer. Test rapid message rates, large rooms, and reconnection storms.

### 217. Presence tracking?

Track which users are online, in which rooms, their status (active, idle, away). Implement via Redis (in-memory, fast), update on connect/disconnect and heartbeat. Broadcast presence changes to interested users.

Challenges: eventual consistency (presence changes propagate), stale status on crashes. Use heartbeats and timeouts for detection. Balance accuracy with overhead.

### 218. Message delivery guarantees?

At-most-once (fire-and-forget, some loss), at-least-once (retry, possible duplicates), exactly-once (no loss, no duplication, hardest). Message ID + idempotent processing prevents duplicate effects even with at-least-once delivery.

Most real-time systems use at-least-once with deduplication (cheaper than exactly-once consensus). Kafka supports all modes; choose based on tolerance for loss vs latency impact.

### 219. Offline handling?

Handle dropped clients: store undelivered messages (bounded queue), resync state (send full state or delta) on reconnect, and timeout stale messages. For critical data, implement client-side persistence (localStorage) and sync with server.

Strategies: message queues (server buffers), event sourcing (replay from log), or snapshots (send last N messages). Complexity increases with offline time; balance coverage and resource constraints.

### 220. Backpressure?

Backpressure is a mechanism slowing producers when consumers can't keep up. Without it, queues overflow and memory surges. Implement via: producer waiting (blocked until consumer processes), dropping old messages, or rate limiting.

TCP has built-in flow control. For application-level Pub/Sub, implement explicit backpressure: if queue depth exceeds threshold, slow producers (return error, drop, or pause). Critical for high-throughput systems to prevent cascading failures.

### 221. Debouncing?

Debouncing delays action until after a timeout from last event (prevents rapid re-firing). Example: user types, debounce 300ms, then send search query. Reduces server load.

Implement client-side with setTimeout. Pair with server-side rate limiting for defense.

### 222. Throttling?

Throttling limits action frequency to at most once per interval (e.g., scroll event fires at max 60/sec). Reduces CPU/network load from high-frequency events.

Implement via scheduled callbacks or request debouncing. Pair rate limiting server-side.

### 223. Event delegation?

Event delegation uses a single listener on a parent for many child events (bubbling). Reduces listeners, improves memory. Useful for dynamic content (e.g., click handler on table delegating to rows).

Understand event bubbling phases (capture, target, bubble) to delegate correctly. Avoid over-delegation (performance trade-offs with filtering logic).

### 224. Browser rendering pipeline?

Steps: parse HTML/CSS → DOM/CSSOM trees → render tree (layout) → paint (draw pixels) → composite (layers). JavaScript blocks parsing. CSS/images block rendering. Optimization: critical path (minimize blocking resources, inline critical CSS), defer non-critical JS.

Use DevTools timeline to identify bottlenecks. Techniques: async/defer scripts, CSS media queries, lazy load images/fonts.

### 225. Layout thrashing?

Layout thrashing is repeated forced layouts (layout, read properties, modify, layout again). Causes jank and poor performance. Example: loop modifying DOM and reading offsetWidth.

Avoid by batching reads/writes: read all properties first, batch DOM changes, then layout recomputes once. Use requestAnimationFrame to group visual updates.

### 226. SEO in React?

React SPAs lack SEO by default (robots see empty HTML). Strategies: server-side rendering (SSR, send rendered HTML), prerendering (build time), or dynamic rendering (detect bots, serve pre-rendered). Use react-helmet or next.js for meta tags, structured data.

For modern bots (Google), CSR with good content works. For older bots or social sharing, implement SSR or prerender. Verify with Search Console.

### 227. SSR vs CSR?

CSR (Client-Side Rendering): browser downloads JS, renders. Fast interaction after load, but slow initial load, poor SEO. SSR (Server-Side Rendering): server renders HTML, sends to client, hydrates. Fast FCP, better SEO, but server load, complex setup.

Use CSR for internal tools, SSR for public content. Next.js enables hybrid: SSR for critical pages, CSR for others. Choose based on performance and SEO requirements.

### 228. Next.js basics?

Next.js is a React framework for SSR, SSG, ISR, and API routes. Pages directory maps to routes, getServerSideProps/getStaticProps for data. Built-in optimizations: code splitting, image lazy load, font optimization.

Simplifies SSR setup, provides structure, and enables hybrid rendering strategies. Standard for production React apps needing SEO or performance.

### 229. Frontend security?

Prevent XSS: escape user input, use DOMContentLoaded (not innerHTML), React auto-escapes. Prevent CSRF: validate origins, use CSRF tokens for forms. Secure storage: HTTPS for transport, localStorage (not cookies) for non-sensitive data. Never store secrets client-side.

Use security headers (CSP, X-Frame-Options), keep dependencies updated, use subresource integrity. Audit regularly with tools (OWASP ZAP, Burp Suite). Security is everyone's responsibility.

### 230. Infinite scroll?

Infinite scroll loads more items as user scrolls near bottom (better UX than pagination for discovery). Implement with IntersectionObserver (trigger load when sentinel element visible), combine with virtualization for large datasets.

Challenges: scroll position loss (on back), SEO (content below fold), state management. Test edge cases: rapid scrolling, network latency, empty states. For products, A/B test against pagination.

## Section 6 — System Design (Q231–Q270)

### 231. Design a chat system?

Core: users connect (WebSocket), send messages, others receive in real-time. Store messages in DB for history. Components: chat server (connection handling, routing), message store (DB/Kafka), user service, file storage (media), notifications.

Scale: shard by room/user, use Redis for online presence, Kafka for durability, multiple servers behind LB. Handle offline users (queue messages), delivery receipts, typing indicators. A/B test UI (real-time vs polling). Expect high concurrency and message volume.

### 232. Design URL shortener?

Core: long URL → short URL (encode hash), lookup short → redirect to long. Database: short URL (key), long URL (value), creation timestamp. Use hash function (MD5/SHA1 first 6-7 chars) to generate shorts, handle collisions (retry with different hash).

Scale: shard by short URL hash, cache hot URLs (Redis), async analytics in parallel. Serve redirects via CDN (low-latency). Handle abuse (rate limit, spam detection). Monitor 404s (broken shorts).

### 233. Design notification system?

Users subscribe to events; system sends notifications (email, SMS, push). Components: event producer (app), queue (Kafka), worker (process notifications), delivery service (email/SMS provider), storage (notification history).

Scale: decouple via queue, parallelize workers, retry failed deliveries, implement backoff. Handle rate limiting (user preferences), batching (cost optimization). Provide templates, scheduling (send later), and unsubscribe.

### 234. Design file storage?

Core: upload file, get metadata, download. Store files on object storage (S3, GCS), metadata in DB. Components: API gateway (auth, rate limit), upload handler, storage backend, cache (CDN).

Scale: multipart uploads (parallel), deduplication (content hash), replication (availability), versioning. Handle large files (torrent download), encryption, and quarantine malicious files. Consider cost (storage, egress bandwidth).

### 235. Design rate limiter?

Limit requests per user/IP to prevent abuse. Algorithms: token bucket (fixed rate, burst), leaky bucket (smooth rate), sliding window (precise, stateful). Store limits in Redis, return 429 with Retry-After.

Design for distributed systems (Redis cluster), variable limits (free/premium), and graceful degradation (allow burst on limit hit). Monitor and alert on unusual patterns.

### 236. Design payment system?

Core: user initiates payment, process via payment gateway (Stripe, PayPal), store transaction, fulfill order. Handle: concurrency (idempotent operations), failures (retries, rollbacks), fraud detection, compliance (PCI, SOX).

Use message queues for async processing, store pending transactions, implement reconciliation with payment gateway. Webhook handling for async confirmations. Zero-downtime upgrades with feature flags. Test thoroughly with test payment methods.

### 237. Design microservices architecture?

Decompose monolith into services (users, orders, payments, inventory, shipping). Each service owns its data, minimal shared state. Communicate via REST/gRPC or events. Use API gateway for unified entry, service discovery (Kubernetes, Consul).

Design for: independent scaling, deployment, tech choices. Document contracts, implement versioning, provide SDKs. Plan for failures (cascades, timeouts, circuit breakers). Operational complexity higher; suitable for large orgs/products.

### 238. Horizontal scaling?

Add more servers (instances) in parallel instead of upgrading single server (vertical). Benefits: handle more load, fault tolerance. Challenges: state sharing (sessions, caches), consistency (eventual), coordination.

Design stateless services, use external state stores (Redis, DB), load balance, and implement health checks. Cost-effective and cloud-friendly (add/remove on demand).

### 239. Vertical scaling?

Upgrade existing server (CPU, RAM). Simple but has limits (hardware ceiling), single point of failure. Sufficient for small services with moderate load.

Combine with horizontal: start vertical (simpler), then horizontal when needed.

### 240. Load balancing?

Distribute traffic across servers. Algorithms: round-robin (even distribution), least connections (lowest active), IP hash (sticky sessions). Layer 4 (TCP) for raw traffic; Layer 7 (HTTP) for smart routing (URL, hostname).

Use health checks, graceful drains, and monitor backend availability. CDN for geographic distribution, API gateway for cross-cutting concerns.

### 241. CDN?

CDN (Content Delivery Network) caches content on edge servers near users, reducing latency and origin load. Perfect for static assets (JS, CSS, images), APIs (regional endpoints).

Configure cache headers, invalidation strategies, and failover to origin. Reduces infrastructure cost and improves user experience significantly.

### 242. Caching layers?

Multi-level caching: CPU cache, application cache (in-memory), distributed cache (Redis), CDN cache, HTTP cache (browser). Each layer reduces load on deeper layers.

Design: identify hot data, TTL, invalidation strategy (event-driven, time-based), and freshness tolerance. Cache stampedes: use collapses queries, probabilistic early expiry. Monitor hit rates.

### 243. Cache invalidation?

Invalidate cache to ensure freshness. Strategies: TTL (time-based), event-based (update event triggers invalidation), LRU (evict old entries), versioning (change key on update).

Classic hard problem: design explicit invalidation. Pair with monitoring for cache misses/staleness anomalies.

### 244. Database scaling?

Optimize within single DB: indices, query tuning, connection pooling. Beyond: read replicas (horizontal read), sharding (horizontal write), caching layer. Replication lag acceptable for reads; sharding adds complexity (transaction, joins across shards).

Choose based on workload: mostly reads → replicas, high-write → sharding. Consider operational overhead.

### 245. Sharding?

Partition data by shard key across multiple DB instances. Enables write scaling. Challenges: even distribution (avoid hotspots), shard rebalancing (expensive), and cross-shard operations (expensive/not transactional).

Plan shard key and rebalancing. Consistent hashing or fixed partition schemes. Use coordination service (ZooKeeper, etcd) for shard topology. Handle shard splits/merges without downtime.

### 246. Replication?

Copy data across instances: primary (writes), replicas (reads). Improves availability and read throughput. Consistency models: strong (sync, slow), weak (async, fast).

Monitor replication lag, handle failover (elect new primary). For critical data, synchronous replication; for analytics, asynchronous. Combine with backups for DR.

### 247. Event-driven systems?

Services publish events (domain events), others subscribe and react. Decouples services, improves scalability. Store events (event store), replay for state reconstruction (event sourcing).

Complexity: eventual consistency, ordering, idempotency. Use Kafka for durability and ordering. Design for distributed tracing, versioning, and backward compatibility.

### 248. Queue-based systems?

Decouple producers/consumers via message queues (Kafka, RabbitMQ, SQS). Producers send messages (async), workers consume. Scales independently.

Benefits: decoupling, resilience (survives consumer downtime), load leveling. Complexity: eventual consistency, debugging. Monitor queue depth, consumer lag.

### 249. Fault tolerance?

Systems fail; design for resilience. Strategies: redundancy (N+1), health checking (detect failures), auto-failover (elect new leader), graceful degradation (shedding non-critical features).

Design for partial failures (some servers down, services slow, network partitions). Use circuit breakers, timeouts, retries. Test failure scenarios (chaos engineering). Document runbooks.

### 250. Circuit breakers?

Stop requests to failing services, return cached/default responses. States: closed (normal), open (failing, short-circuit), half-open (test recovery). Configurable thresholds (consecutive failures, error rate).

Prevent cascading failures. Pair with exponential backoff for retries. Monitor state changes and alert. Libraries: Resilience4j, Hystrix.

### 251. Monitoring?

Observe system health: uptime, error rates, latency, throughput, cost. Collect metrics (Prometheus, Datadog), logs (ELK, Loki), traces (Jaeger). Alert on anomalies.

Custom metrics for domain logic. Distinguish symptoms (high latency) from causes (slow DB). Dashboard for visibility, runbooks for response. Continuous improvement from monitoring insights.

### 252. Observability?

Observability answers "what happened" from system outputs (logs, metrics, traces). Monitor multiple systems (infrastructure, app, DB) together. Structured logging (JSON), correlation IDs across requests, distributed tracing.

Better than alerting: proactive diagnosis, anomaly detection, capacity planning. Tools: Honeycomb, DataDog, New Relic. Invest in observability; it pays off in incident response.

### 253. Logging architecture?

Centralized logging: applications log to aggregator (Fluentd, Logstash), stored (Elasticsearch), indexed (Kibana). Enables search/alerting across all services.

Design: structured logs (JSON), contextual data (user ID, trace ID), severity levels. Filter high-volume logs (sample). Cost: storage and compute for indexing. Balance visibility and cost.

### 254. Metrics?

Metrics capture numeric data (latency, requests, errors, memory). Time-series DBs store efficiently (Prometheus, InfluxDB). Alert on thresholds, track trends.

Types: counters (monotonic, request count), gauges (current value, memory), histograms (distributions). Cardinality explosion (too many label combinations) kills systems; design carefully.

### 255. Distributed tracing?

Trace a request end-to-end across services, showing spans (service calls) and latency. Tools: Jaeger, Zipkin. Enables fault diagnosis ("where did it slow?"). Pair with logs and metrics.

Sampling (not all traces, cost) vs. full tracing (visibility). Correlation IDs propagate trace context. Critical for microservices debugging.

### 256. Consistency models?

Strong consistency (all replicas always agree, slower), weak consistency (replicas may diverge, eventual consistency — all converge given time, faster). CAP theorem: choose consistency or availability under partition.

Most systems choose eventual consistency for availability/speed. Design apps to tolerate stale data, use versioning, implement compensating transactions if needed.

### 257. CAP theorem?

Consistency (all replicas same), Availability (system always responds), Partition tolerance (survives network splits). Can't have all three; partition tolerance is non-negotiable in distributed systems.

Choose: CP (prioritize data integrity), AP (prioritize availability/resilience). Systems often tune one dimension (consistency strength, replication latency).

### 258. Data partitioning?

Partition data by range (date, ID) or hash (ID mod N) for scalability. Range allows efficient range queries but can create hotspots (popular date range). Hash distributes evenly but loses range query benefit.

Design partition key carefully (stable, uniform distribution). Monitor hotspots and rebalance if needed. Larger partitions; fewer partitions.

### 259. High availability?

Systems tolerate failures and maintain service. Patterns: redundancy, health monitoring, automated failover, graceful degradation. RTO (recovery time), RPO (data loss tolerance) guide design.

Multi-region for geo-resilience. Data replication, leader election, and coordination services essential. Test failovers regularly, document runbooks, maintain on-call rotations.

### 260. Disaster recovery?

Plan for catastrophic failure (datacenter down, data corruption). Backup to geographically distant region, test recovery regularly. RTO (how fast to recover), RPO (how much data loss acceptable).

Automated backups, versioning, and point-in-time recovery. For critical data, near-sync replication (acceptable RPO). Document recovery procedures and test them.

### 261. Multi-region deployment?

Deploy services across regions (continents) for latency (serve users locally), availability (survive region failure), and compliance (data residency). Challenges: data consistency (eventual), operational complexity, cost.

Primary-replica or multi-master replication. Route users to nearest region. Test failover between regions. Coordinate deployments. Monitor latency and replication lag.

### 262. Stateless vs stateful?

Stateless services don't hold client data (easily replicated, scalable). Stateful services store client state (persistent, harder to scale). Prefer stateless; store state in DB/cache. Stateful is acceptable for session-specific data (cache connections temporarily).

Design: decouple state from compute. Enables horizontal scaling, zero-downtime deployments.

### 263. Idempotency?

Idempotent operations return the same result if executed multiple times. Critical for retries: if request fails, retry safely without duplicating effect. Implement via idempotency keys (client ID + request ID) mapped to responses.

Design APIs to be idempotent (PUT, DELETE naturally are). Store recent responses (Redis) for deduplication. Essential for distributed, fault-prone systems.

### 264. Retry strategies?

Retry failed requests with exponential backoff (1s, 2s, 4s, ..., max) and jitter (randomize to avoid thundering herd). Circuit breakers prevent retrying failing services. Idempotency enables safe retries.

Not all errors are retryable (4xx errors, usually not; 5xx, often retryable). Document retry policies. Avoid retry storms (rate limit, max retries).

### 265. Backoff algorithms?

Exponential backoff: wait increases exponentially per retry (2^attempt * base). Linear backoff: increases linearly. Jitter: add randomness to prevent synchronized retries.

Exponential favored for cascading failures (load decreases faster). Configure max wait (prevent forever waits). Test under real failure scenarios.

### 266. API design at scale?

Version APIs (URL path, header), maintain backward compatibility, use hypermedia (HATEOAS, links) for discoverability. Paginate results, sort stably, filter server-side. Rate limit, authenticate, authorize. Document with OpenAPI.

Status codes: 200 (OK), 201 (Created), 204 (No Content), 400 (Bad Request), 401 (Unauthorized), 403 (Forbidden), 404 (Not Found), 409 (Conflict), 429 (Rate Limited), 500 (Server Error). Be consistent.

### 267. Security at scale?

Defense-in-depth: secure transport (TLS), authentication (OAuth2, SAML), authorization (RBAC, ABAC), input validation (SQL injection, XSS), secrets management (Vault), audit logging. Encrypt at rest and in transit.

Regular security audits, dependency updates, penetration testing. Breach response procedures. Compliance (GDPR, HIPAA, PCI). Security is not an afterthought.

### 268. Cost optimization?

Measure cloud costs (compute, storage, egress bandwidth). Optimize: right-size instances, reserved capacity, auto-scaling, caching, compression, CDN. Monitor and alert on anomalies.

Balance cost and performance. Prefer managed services when operational overhead isn't justified. Negotiate volume discounts with cloud providers. FinOps practices help.

### 269. Performance optimization?

Profile identify bottlenecks (CPU, memory, I/O, network). Optimize incrementally: algorithms, caching, batching, async, parallel processing. Measure before/after. Keep performance regressions from accumulating.

Use APMs (Datadog, New Relic) for continuous monitoring. Load test and capacity plan. Optimize expensive code paths. Test at scale.

### 270. Trade-off decisions?

Architecture involves constant tradeoffs: consistency vs availability, latency vs throughput, simplicity vs performance, cost vs capability. Document reasoning: why this choice, not alternatives, tradeoffs accepted.

Revisit as requirements change. Be pragmatic: early premature optimization risks; late optimization is expensive. Measure, decide, validate.

## Section 7 — AWS / DevOps (Q271–Q290)

### 271. AWS architecture basics?

AWS provides cloud services: compute (EC2, Lambda), storage (S3, EBS), database (RDS, DynamoDB), networking (VPC, ALB), messaging (SQS, SNS), and more. Design for high availability (multi-AZ), scalability (auto-scaling), and cost-efficiency.

Use managed services to reduce operational burden. Design for failure (redundancy, backups, DR). Security groups control inbound/outbound, IAM grants permissions. Cost: pay-as-you-use; monitor and optimize.

### 272. EC2?

EC2 (Elastic Compute Cloud) provides virtual machines (instances) on-demand. Choose instance type (CPU, RAM, storage, network), OS, security group. Scale via auto-scaling groups (add/remove instances based on load). Cost: on-demand, reserved (cheaper), spot (cheapest, interruptible).

Design: stateless, idempotent instances replaced easily. Pair with load balancers and health checks. Use Terraform/CloudFormation for infrastructure-as-code.

### 273. S3?

S3 (Simple Storage Service) is object storage: store/retrieve files (buckets, keys). Scalable, durable (11 9's), available globally. Pricing: storage, requests, transfer. Integrates with CloudFront (CDN), S3 Select (query in-place), Glacier (archival).

Design: use versioning, enable logging, secure with bucket policies/ACLs, use SSE (encryption). Lifecycle policies transition old objects to cheaper tiers. Multipart uploads for large objects.

### 274. RDS?

RDS (Relational Database Service) is managed SQL database (PostgreSQL, MySQL, Oracle, SQL Server). Handles backups, patches, replication (multi-AZ for HA). Scaling: upgrade instance size (vertical) or read replicas (read-only, horizontal).

Cheaper than self-managed, but less control. Monitor performance (metrics), use parameter groups for tuning. Plan capacity, monitor costs (storage, IOPS).

### 275. DynamoDB?

DynamoDB is NoSQL, fully managed, serverless (no capacity planning). On-demand or provisioned throughput. Supports single-digit latency at scale, global tables (multi-region).

Limitations: no joins, eventual consistency by default, limited query patterns (design around partition key). Strong eventually consistent reads cost more. Good for real-time, high-throughput applications.

### 276. Lambda?

Lambda is serverless compute: upload code, AWS manages infrastructure. Pay for execution time (milliseconds), not idle. Auto-scales, event-driven (S3 upload, API Gateway, SQS, etc.).

Limitations: timeout (15 min), cold start latency, environment constraints (languages, libraries). Good for event-driven, occasional workloads. Not for long-running tasks or those needing persistent state.

### 277. API Gateway?

API Gateway provides REST/HTTP API frontend, routes to Lambda, EC2, or other backends. Handles: request validation, transformation, authentication, rate limiting, logging.

Enable CORS, request/response mapping, request caching. Use stages (dev, prod). Pair with Lambda for serverless APIs. Simpler ALB for complex routing (multiple backends, protocols).

### 278. CloudFront?

CloudFront is AWS's CDN: cache content on edge locations globally. Reduce latency for users, offload origin. Supports HTTP/2, HTTP/3, DDoS protection (Shield).

Configure origins (S3, ALB, custom), cache behaviors (by path, header), invalidation (after deployments). Cost: data transfer (cheaper than origin), requests.

### 279. IAM?

IAM (Identity and Access Management) grants AWS resource permissions. Principle of least privilege: grant only needed permissions. Resources (S3 bucket, EC2 instance), actions (s3:GetObject), principals (users, services).

Policies are JSON. Use roles for services (Lambda, EC2 accessing other services). Enable MFA for human users, rotate keys. Audit with CloudTrail. Complex but critical for security.

### 280. VPC?

VPC (Virtual Private Cloud) isolates network: subnets (AZs), route tables (routing), security groups (stateful firewall), NACLs (network access control, stateless). Design: public subnets (ALB, NAT), private subnets (apps, DB).

Use VPC peering or Transit Gateway to connect VPCs. Enable VPC Flow Logs for debugging. Cost: minimal, but data transfer across regions expensive.

### 281. Load balancer types?

ALB (Application Load Balancer): Layer 7 (HTTP), route by hostname/path, target groups. NLB (Network Load Balancer): Layer 4 (TCP/UDP), ultra-high throughput, low latency. CLB (Classic): older, simpler.

Use ALB for most web apps, NLB for extreme performance or non-HTTP protocols. Health checks ensure traffic only to healthy targets. Pricing per LB and processed bytes.

### 282. Auto scaling?

Auto Scaling Groups (ASG) add/remove EC2 instances based on metrics (CPU, custom). Define min, max, desired capacity. Policies: target tracking (maintain target metric), step scaling (based on alarm thresholds).

Pair with health checks and instance refresh for zero-downtime deployments. Cost: save money by scaling down during off-hours. Test scaling behavior under load.

### 283. Docker?

Docker containerizes applications: package code, dependencies, config as images. Containers are lightweight, portable, reproducible. Docker Compose orchest rates local containers; Docker Swarm or Kubernetes orchestrate at scale.

Build: Dockerfile defines layers (FROM, RUN, COPY, CMD). Push to registry (AWS ECR, Docker Hub). Run with resource limits. Security: scan images (Trivy, ECR scanning), use minimal base images.

### 284. Containerization?

Containers enable consistent deployment (works on dev, prod), rapid scaling, resource isolation. Orchestrators (Kubernetes, ECS) manage scheduling, networking, storage.

Mindset: loosely-coupled, stateless containers. Log to stdout (captured by orchestrator). Use health checks. Versioning: tag images semantically (v1.2.3).

### 285. Kubernetes basics?

Kubernetes orchestrates containers: nodes (machines), pods (containers), deployments (replicas), services (networking). YAML manifests define desired state; K8s reconciles to it.

Features: auto-scaling, self-healing, rolling updates, service discovery. Complexity: requires operational expertise. Managed K8s (EKS, GKE) reduce operational burden.

### 286. CI/CD pipelines?

CI (Continuous Integration): on every commit, build, test, push artifacts. CD (Continuous Deployment): automatically deploy to production. Tools: GitHub Actions, GitLab CI, Jenkins, CircleCI.

Design: fast feedback (10-15 min builds), parallel testing, automated deployments. Stages: lint, unit tests, integration tests, deploy to staging, deploy to prod (possibly manual approval). Rollback procedures.

### 287. Deployment strategies?

Blue-green: run two identical envs, switch traffic. Rolling: gradually replace old instances. Canary: route small traffic % to new version, monitor, expand. Feature flags: enable features per user without deployment.

Choose based on risk tolerance and rollback needs. Test deployments in staging. Automate rollback. Monitor for issues (error rates, latency).

### 288. Monitoring (CloudWatch)?

CloudWatch (AWS's monitoring service) collects metrics (EC2, RDS, Lambda), logs (applications, AWS services), and enables alarms. Custom metrics: publish application metrics.

Dashboard for visibility, alarms for notifications (SNS, PagerDuty). Logs Insights for querying (SQL-like). CloudTrail logs API calls for audit/compliance. Cost: storage and data scanned.

### 289. Infrastructure as Code?

IaC (Terraform, CloudFormation, CDK) defines infrastructure in code: versioned, reproducible, reviewable. Benefits: consistency, disaster recovery (redeploy), automation, documentation.

Terraform is provider-agnostic (AWS, GCP, Azure). CloudFormation is AWS-native, simpler for AWS-only. Modularize, test changes in staging, plan before applying. Secrets management (Vault, AWS Secrets Manager).

### 290. Security groups vs NACL?

Security groups (stateful): inbound/outbound rules per instance. NACLs (stateless): rules per subnet, require explicit return rules. Security groups are simpler, sufficient for most use cases.

NACLs provide defense-in-depth but are harder to reason about. Default deny, explicitly allow. Monitor and log (VPC Flow Logs).

## Section 8 — Security / Engineering Practices (Q291–Q300)

### 291. OWASP Top 10?

Top vulnerabilities: injection (SQL, command), broken auth, sensitive data exposure, XML external entities (XXE), broken access control, security misconfiguration, XSS, insecure deserialization, using components with known vulnerabilities, insufficient logging/monitoring.

Mitigate: input validation, parameterized queries, strong auth, encryption, regular updates, WAF, security headers. Annual updates reflect evolving threats.

### 292. SQL injection prevention?

Attacker inserts SQL via input (unsanitized). Prevent: parameterized queries/prepared statements (SQL template + data), input validation (whitelist), least privilege (DB user has minimal permissions).

Never concatenate SQL. Use ORM frameworks that use prepared statements by default (Hibernate, Entity Framework). Test with fuzzing.

### 293. XSS prevention?

Attacker injects scripts into pages. Prevent: escape output (context-aware: HTML, JS, URL, CSS escape), use frameworks auto-escaping (React auto-escapes), Content Security Policy (CSP, restrict script sources).

Use HTTPS, set secure/httponly flags on cookies. Sanitize user input for safe outputs (OWASP DOMPurify).

### 294. CSRF protection?

Attacker tricks user's browser to perform unwanted actions on authenticated site. Prevent: CSRF tokens (unique per request, validated server-side), SameSite cookies, origin checking, require POST for state-changing ops (not GET).

Tokens in forms; validate on server. SameSite (Strict/Lax) prevents cross-site cookie sending. For stateless APIs, CSRF is less relevant if not using cookies.

### 295. JWT security?

Don't store secrets in JWT (observable in token). Use short-lived tokens (15 min), refresh tokens (longer-lived) for renewal. Validate signature (verify against key), expiry, audience, issuer.

Use strong algorithms (RS256, not HS256 with weak secret). Ensure secure transport (HTTPS). Consider token rotation and revocation lists for sensitive operations.

### 296. HTTPS working?

HTTPS encrypts transport via TLS/SSL. Handshake: client and server exchange keys, encrypt subsequent data. Certificates bind identity (domain) to public key; trusted CAs issue certs.

Enable HSTS (enforce HTTPS), use strong ciphers (TLS 1.2+), rotate certificates before expiry. Cost: minimal (free via Let's Encrypt). Performance: negligible with modern hardware/protocols (HTTP/2, TLS 1.3).

### 297. Encryption basics?

Symmetric (same key to encrypt/decrypt, fast, key distribution hard): AES-256. Asymmetric (public key to encrypt, private key to decrypt, slow): RSA, ECDSA. Hash (one-way, collision-resistant): SHA-256.

Use symmetric for at-rest encryption (database, files); asymmetric for key exchange. Never invent crypto; use libraries. Secure key storage (Vault, HSM).

### 298. Secure coding practices?

Principle of least privilege: grant minimal permissions. Input validation: whitelist, sanitize. Output encoding: context-aware escaping. Dependency management: update regularly, audit for vulnerabilities (SAST, DAST).

Code review for security, static analysis (SonarQube, Semgrep), dynamic testing. Logging (without secrets), monitoring for anomalies. Security training for team.

### 299. Code review practices?

Code review catches issues early (bugs, security, quality). Process: author submits PR, reviewers suggest improvements, iterate, merge. Tools: GitHub, GitLab, Gerrit.

Review for: correctness, performance, security, style, tests. Avoid review fatigue (too many files). Automate trivial checks (linting, tests). Foster psychological safety; constructive feedback.

### 300. Handling production incidents?

Incident: service or system failure impacting users. Process: detect (alerting), triage (severity, impact), mitigate (restore functionality), investigate (root cause), remediate (fix), post-mortem (learnings).

On-call responsibilities: respond quickly, communicate with stakeholders, execute runbooks. Blameless culture: focus on systems, not individuals. Document post-mortems, implement action items. Regular incident simulations (games) improve preparedness.

---

## Section 8: Advanced Spring & Microservices (Q301–350)

### 301. Spring auto-configuration internals?

Auto-configuration auto-configures Spring context based on classpath dependencies. Uses @Configuration, @ConditionalOnClass, @ConditionalOnProperty, @ConditionalOnMissingBean to conditionally create beans.

Spring Boot scans META-INF/spring.factories for auto-configuration classes. Executes them in order via @AutoConfigureOrder or @AutoConfigureAfter. User's explicit @Bean definitions override via @ConditionalOnMissingBean.

Example: spring-boot-starter-web adds Spring MVC auto-config. spring-boot-starter-data-jpa configures DataSource, EntityManagerFactory, TransactionManager if not already defined.

Understand: order matters (database config before JPA config). Use spring.factories SPI for custom auto-configs. Disable auto-config with @SpringBootApplication(exclude={...}). Test: create application.yml, annotate test with @SpringBootTest, use @TestPropertySource to verify conditional activation.

### 302. BeanPostProcessor in Spring?

BeanPostProcessor intercepts bean creation lifecycle (after instantiation, before/after initialization). Allows modifying bean properties, wrapping beans, or creating proxies.

Two methods: postProcessBeforeInitialization (before @PostConstruct, InitializingBean.afterPropertiesSet()), postProcessAfterInitialization (after init methods, often creates proxies for AOP).

Example: auto-wire custom annotations, wrap beans with logging, create proxies for transaction management. Spring uses: CommonAnnotationBeanPostProcessor (@PostConstruct, @PreDestroy), AutowiredAnnotationBeanPostProcessor (@Autowired), RequiredAnnotationBeanPostProcessor (@Required).

Advanced: register via @Bean, implement Ordered to control execution order. Pitfall: BeanPostProcessor called for every bean; keep logic efficient. Use responsibly; misuse causes initialization order issues, infinite cycles, or hard-to-debug behavior.

### 303. ApplicationContext lifecycle?

ApplicationContext creation: instantiate context (ClassPathXmlApplicationContext, AnnotationConfigApplicationContext), scan for beans, invoke BeanFactoryPostProcessors, instantiate beans (constructor → dependency injection → BeanPostProcessors → init methods).

Startup events: ContextRefreshedEvent (after all beans initialized). Shutdown: ContextClosedEvent (on context.close() or JVM exit).

Key phases: Bean definition loading → Bean instantiation → Property setting → BeanPostProcessor callbacks → Context ready (ContextRefreshedEvent) → Shutdown (destroy methods, ContextClosedEvent).

Understand: initialization is synchronous; blocking in @PostConstruct delays startup. Use startup/shutdown hooks wisely. Test: use @SpringBootTest, verify beans via ApplicationContext.getBean(). Monitor: use Spring Boot Actuator (startup time endpoint).

### 304. Spring AOP overview?

AOP (Aspect-Oriented Programming) separates cross-cutting concerns (logging, security, monitoring) from business logic. Aspects encapsulate advice (code to run) with pointcuts (where to run).

Advice types: @Before (pre-method), @After (post-method, always), @AfterReturning (on success), @AfterThrowing (on exception), @Around (wrap method, most powerful).

Pointcuts: expressions matching methods. Example: @Around("execution(* com.example.service.*.*(..))")—advice wraps all methods in service package.

Spring AOP: proxy-based (runtime), supports method-level interception. Cglib proxies for concrete classes, JDK proxies for interfaces. Limitation: only method calls via proxy; direct invocations skip AOP.

Common use cases: @Transactional, custom annotations (caching, logging), security checks. Advanced: load-time weaving for non-proxy scenarios.

Pitfall: forgetting @EnableAspectJAutoProxy. Performance: proxy overhead; avoid overuse. Testing: mock aspects; use @WithMockUser.

### 305. Transaction proxy mechanism?

@Transactional creates a proxy around method. On invocation: proxy intercepts → begins transaction → calls actual method → on success commit → on exception rollback (if matching @Transactional(rollbackFor=...)) → closes connection.

Proxy-level: only works for method calls via proxy (autowired bean), not direct calls (this.method()). Requires @EnableTransactionManagement (enabled by default in Boot).

Propagation: REQUIRED (reuse existing, create if none), REQUIRES_NEW (always new), NESTED (savepoint), MANDATORY (must exist), SUPPORTS (use if exists).

Isolation: READ_UNCOMMITTED, READ_COMMITTED (default), REPEATABLE_READ, SERIALIZABLE (strictness vs. performance).

Pitfall: method visibility (must be public/package-protected), rollback rules (unchecked exceptions roll back; checked don't). Nested transactions: REQUIRES_NEW is expensive; use NESTED (savepoints).

Testing: @Transactional on test rolls back after test. Use @Transactional(propagation=PROPAGATION_NOT_SUPPORTED) to disable per test.

### 306. Distributed transaction patterns?

Distributed transactions span multiple databases/services. ACID guarantee is hard; use eventual consistency patterns.

**Two-Phase Commit (2PC)**: coordinator prepares participants (locks resources), then commits. Complex, blocking, poor availability. Avoid in microservices.

**Saga Pattern**: long-running transaction split into steps. Each step is local transaction on one service. Orchestration: central coordinator issues commands. Choreography: services emit events, others listen and react.

Example (payment): OrderService creates order → PaymentService charges card → InventoryService reserves stock. If payment fails, emit RollbackEvent, compensate.

Trade-off: eventual consistency (temporary inconsistency), complexity (handle rollbacks). Tools: Spring Cloud Data Flow, Axon Framework, Saga libraries.

**Idempotency**: ensure retry-safety. Use correlation IDs. Store processed IDs; if retried with same ID, return cached result.

### 307. Saga pattern implementation?

**Orchestration**: 
```java
@Service
public class OrderSaga {
  public void createOrder(Order order) {
    orderId = orderService.create(order);
    try {
      paymentClient.charge(order.getPrice());
      inventoryClient.reserve(order.getItems());
    } catch (Exception e) {
      compensate(orderId);
    }
  }
}
```

**Choreography**: Services trigger events, others listen. OrderService emits OrderCreated, PaymentService listens, charges card, emits PaymentCharged.

Orchestration: easier to understand, single point of control. Choreography: decoupled, event-driven, harder to trace.

Trade-offs: Orchestration: centralized, single failure cascades. Choreography: distributed, but circular dependencies possible. Both support eventual consistency; implement idempotency, store saga state, timeout handling.

Testing: orchestration easier (mock clients). Choreography requires event-driven test setup.

Tools: Axon Framework, Temporal, Camunda.

### 308. Circuit breaker pattern?

Circuit breaker prevents cascading failures. Monitors service calls; if failure rate exceeds threshold, stops calls (fast fail), gives service time to recover.

States: Closed (normal), Open (threshold exceeded, calls rejected immediately), Half-Open (after timeout, retry call).

Example (Resilience4j):
```java
@CircuitBreaker(name = "paymentService", fallbackMethod = "fallback")
public Payment processPayment(Order order) {
  return paymentClient.charge(order);
}

public Payment fallback(Order order, Exception e) {
  return new Payment(status="PENDING");
}
```

Configuration: failureThreshold (5 failures), slowCallDurationThreshold (2s), slowCallRateThreshold (50%).

Benefits: prevents resource exhaustion, fast fail, recovery time.

Pitfall: not end-to-end solution. Combine with retry (exponential backoff), timeout, fallback. Fallback logic must be safe.

Monitoring: track circuit state changes, alert on prolonged open.

### 309. Resilience4j patterns?

Resilience4j provides: Bulkhead (thread pool isolation), Retry (exponential backoff + jitter), RateLimiter (limit request rate), Timeout (cancel call if too slow), Cache (cache successful responses).

Example:
```java
@Bulkhead(name = "paymentService", type = THREAD_POOL)
@Retry(name = "paymentService")
@Timeout(name = "paymentService")
public Payment process(Order order) { ... }
```

Composition: combine multiple patterns. Use @Retry + @CircuitBreaker (retry first, then circuit break).

Monitor via Micrometer/Prometheus.

Pitfall: configuration complexity. Start simple (circuit breaker only), add others as needed. Ensure timeout < retry deadline.

### 310. Service mesh basics (Istio/Linkerd)?

Service mesh: infrastructure layer managing service-to-service communication. Uses sidecars (lightweight proxies) alongside each service.

**Istio**: Control plane (Istiod configures proxies), Data plane (Envoy sidecars handle traffic). Features: traffic management (routing, load balancing), security (mTLS, authorization), observability.

Example (routing):
```yaml
VirtualService:
  name: payment-vs
  http:
  - match:
    - uri:
        prefix: /v1
    route:
    - destination:
        host: payment
        port:
          number: 8080
```

**Linkerd**: simpler, lighter-weight. Less feature-rich; good for getting started.

Benefits: decouples communication logic, transparent mTLS, circuit breaking, retry, timeout at infrastructure level, observability without code changes.

Trade-off: operational complexity, latency overhead, resource consumption.

When to use: 10+ services, complex traffic management, strong security requirements.

### 311. Observability (metrics, logs, traces)?

Observability: understand system behavior via metrics, logs, traces (three pillars).

**Metrics**: numerical data (requests/sec, latency, errors). Time-series (Prometheus). Export via Micrometer.

**Logs**: structured events. Export to Elastic, Splunk. Use JSON format.

**Traces**: end-to-end request flow. Tools: Jaeger, Zipkin. Propagate correlation ID (X-Trace-ID) across services.

Stack: Spring Cloud Sleuth → Jaeger/Zipkin. Metrics → Prometheus → Grafana. Logs → Elasticsearch → Kibana.

Pitfall: high cardinality metrics cause storage issues. Avoid per-user ID as metric label. Sampling: trace all in dev, sample in prod (10%).

### 312. Event sourcing pattern?

Event sourcing: store all state changes as immutable events. Current state derived by replaying events.

Example: instead of storing account balance, store events: AccountCreated, MoneyDeposited, MoneyWithdrawn. Replay events → balance.

Benefits: auditability (full history), temporal queries (state at any point), recovery (replay from snapshot + events), event-driven architecture.

Trade-offs: Pro: complete audit trail, decoupled from state model. Con: eventual consistency, complexity (event versioning), storage overhead.

Pitfall: event versioning (handle structure changes). Use snapshots (periodic full state) to speed up replay.

Tools: Axon Framework, EventStore, Apache EventMesh.

### 313. CQRS pattern?

CQRS (Command Query Responsibility Segregation): separate read and write models. Write model optimized for commands, read model optimized for queries (denormalized).

Example: Write model accepts CreateOrderCommand, stores event (normalized schema). Read model consumes events, maintains denormalized view. Query: fetch from read model (fast, no joins).

Benefits: scalability (independent read/write scaling), read optimization (no joins), independence (different DB: Elasticsearch, Redis).

Pitfall: eventual consistency (read model lags writes). Mitigate: include version number in write response; client checks version.

Implementation: OrderCommandHandler handles command, publishes event. OrderReadModelProjector consumes event, updates denormalized view.

Tools: Axon, event-sourcing libraries + async projections.

### 314. Contract testing in microservices?

Contract testing: validate service contracts (API contracts) without full integration. Consumer defines contract, provider verifies implementation.

Tools: Pact (consumer-driven), Spring Cloud Contract (provider-driven).

**Pact flow**: Consumer writes test → Pact generates mock server → Consumer test verifies → Export contract. Provider consumes contract, verifies implementation matches.

Benefit: catch API mismatches early. Decoupled testing. Regression detection.

Pitfall: contract drift (contract not updated with API changes). Use in CI/CD: consumer test publishes contract, provider test verifies, blocks merge if mismatch.

### 315. Feature flags in Spring?

Feature flags toggle features on/off without deployment. Use for gradual rollout, A/B testing, safe rollbacks.

Example:
```java
@Component
public class OrderFeatures {
  private FeatureFlags flags;
  
  public boolean isV2PaymentEnabled() {
    return flags.isPaymentV2Enabled();
  }
}

if (features.isV2PaymentEnabled()) {
  chargeV2(order);
} else {
  chargeV1(order);
}
```

Runtime toggle: fetch flags from config server or feature flag service (LaunchDarkly, Unleash).

Benefits: zero-downtime deployments, gradual rollout (10% users), quick rollback, A/B testing.

Pitfall: flag clutter. Cleanup: retire flags after full rollout.

### 316. Graceful shutdown in Spring Boot?

Graceful shutdown: on JVM shutdown signal, stop accepting new requests, allow in-flight requests to complete, then terminate.

Configuration:
```yaml
server:
  shutdown: graceful
  tomcat:
    shutdown-wait-time: 30s
```

Lifecycle: Receive SIGTERM → Stop accepting new requests → Wait for in-flight requests → Close database connections, shut down thread pools → JVM exits.

Pitfall: long-running requests may timeout. Consider queue-based approaches (accept requests, queue async workers; on shutdown, allow workers to finish).

Testing: send SIGTERM, verify requests complete (no 503s), monitor cleanup logs.

### 317. Multi-tenancy in Spring?

Multi-tenancy: single application serves multiple isolated tenants. Data and configuration segregated per tenant.

Approaches: Database per tenant (easy isolation, complex cross-tenant operations). Schema per tenant (balance). Row-level isolation (cost-effective, risk of leaks).

Implementation (row-level):
```java
@Component
public class TenantInterceptor implements HandlerInterceptor {
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
    String tenantId = request.getHeader("X-Tenant-ID");
    TenantContext.setTenantId(tenantId);
    return true;
  }
}

@Query("SELECT o FROM Order o WHERE o.tenantId = :tenantId")
List<Order> findByTenant(@Param("tenantId") String tenantId);
```

Security: validate tenant context matches user. Prevent cross-tenant data access.

### 318. mTLS (mutual TLS)?

mTLS: client and server both authenticate using certificates.

Setup: CA issues certificates to client and server. Client presents certificate to server, server verifies. Server presents certificate to client, client verifies. Encrypted communication.

Benefits: prevents MITM attacks, ensures both parties trusted.

Configuration (Spring):
```yaml
server:
  ssl:
    key-store: keystore.p12
    key-store-password: changeit
    client-auth: NEED
```

Pitfall: certificate rotation, expiration handling. Use cert management tools (Let's Encrypt, internal CA).

### 319. Data consistency strategies?

Distributed systems sacrifice consistency for availability/partition tolerance (CAP theorem).

**Strong consistency**: all nodes see same data. Expensive (coordination). Examples: RDBMS, primary-backup.

**Eventual consistency**: temporary inconsistency, converges. Cheap. Examples: DNS, social feeds, read replicas.

**Causal consistency**: related operations ordered. Example: add comment after post.

**Bounded staleness**: guarantee freshness (data no older than X seconds). Example: Google Spanner.

Strategies: Optimistic concurrency (version numbers). Pessimistic concurrency (locks). Event sourcing + CQRS (separate read/write). Quorum reads/writes (stronger than eventual).

Trade-off: consistency vs. latency/availability. Choose based on use case: financial (strong), social (eventual).

### 320. Handling schema evolution?

Schema evolution: changing database schema over time (add columns, rename, deletions, type changes).

Strategies: Backward compatible (add optional columns, accept null). Forward compatible (older code understands new data). Zero-downtime (deploy code handling both old/new schema, migrate data, deploy code using new schema).

Tools: Flyway, Liquibase (version migrations).

Pitfall: dropping columns breaks old code. Always deprecate, warn, then remove.

API evolution: semantic versioning, deprecation headers (/v1, /v2). Consumer gives time to migrate.

### 321. Load balancing strategies?

Load balancer distributes requests across servers.

Algorithms: Round-robin (fair, no server health awareness). Least connections (better under uneven load). Weighted (assign weights based on capacity). IP hash (session affinity). Response time (send to fastest).

Tools: Nginx, HAProxy, AWS ELB, Spring Cloud Load Balancer.

Sticky sessions: client routes to same server (preserves session state). Trade-off: if server fails, client disconnects. Prefer: externalize session (Redis).

Health checks: periodically ping servers, remove unhealthy.

### 322. Caching layers?

Caching improves performance by reducing backend load.

**Layers**: Client cache (browser, HTTP cache headers). CDN (geographic distribution, cache at edge). App cache (in-memory: Caffeine, distributed: Redis). Database cache (query results). Disk cache (filesystem).

Trade-off: staleness (cache lag), invalidation complexity.

Strategy (cache-aside):
```java
public Order getOrder(Long orderId) {
  Order order = cache.get(orderId);
  if (order == null) {
    order = database.findById(orderId);
    cache.put(orderId, order);
  }
  return order;
}
```

Invalidation: TTL, event-based, explicit (cache.evict()).

Pitfall: stale data (cache not invalidated). Use versioning, cache tags.

Monitoring: hit rate, eviction rate, memory usage.

### 323. Database replication?

Replication: copy data across servers for reliability and read scaling.

Types: Master-Slave (master accepts writes, slaves replicate asynchronously. Read scaling, single write point). Multi-master (multiple masters accept writes, replicate. Complex conflict resolution, better availability).

Consistency: replication lag (slave slightly behind master). Use master for reads after writes, slaves for read-heavy.

Failover: if master fails, promote slave. Requires coordination (Zookeeper, Raft).

Implementation: MySQL semi-sync, PostgreSQL streaming, MongoDB replica sets.

Pitfall: split-brain (network partition, multiple masters). Use consensus (Raft) to choose leader.

### 324. Database sharding?

Sharding: partition data across multiple databases by key (user ID, region).

Shard key: determines which database stores data. Example: user_id % 10 = shard 0–9.

Benefits: horizontal scaling, data locality, independent backups.

Challenges: Hot shards (uneven distribution). Cross-shard queries (expensive). Resharding (rebalance data on adding/removing shards).

Implementation: application layer (app determines shard), middleware (proxy intercepts).

Tools: Vitess (MySQL sharding proxy), Django ORM sharding.

Operational: monitor shard imbalance, use consistent hashing for resharding.

### 325. Database indexing strategies?

Indexes speed up queries by allowing fast lookups (avoid full table scans).

Types: B-tree (default, supports range queries). Hash (fast exact match, no range). Full-text (search text fields). Bitmap (low-cardinality columns).

Composite indexes: (country, city) allows: WHERE country=X AND city=Y (fast), WHERE country=X (fast), but WHERE city=Y (slow).

Trade-off: indexes slow inserts/updates. Space overhead.

Query optimization: EXPLAIN PLAN shows if index is used. Avoid: SELECT * (scan all columns), expressions on indexed column (WHERE age+1 > 30), OR conditions (may not use index).

Pitfall: unused indexes (bloat). Regularly audit indexes.

### 326. Monitoring database performance?

Key metrics: query latency (p50, p95, p99), QPS (queries/sec), connections, replication lag, slow queries.

Slow query log:
```sql
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;
```

Tools: Datadog, New Relic, Prometheus + custom exporters.

Connection pooling: monitor pool size, idle connections, wait time. Use HikariCP.

### 327. Async processing patterns?

Async: decouple request from response. Return quickly, process in background.

Patterns: Fire-and-forget (submit task, no callback). Future/Callback (submit task, get future. Block or callback when ready). Reactive (subscribe to events, process on arrival).

Implementation (Spring):
```java
@Async
public void processAsync(Order order) {
  paymentService.charge(order);
  inventoryService.reserve(order);
}
```

Trade-off: responsiveness, eventual consistency.

Tools: Spring @Async, Kafka async, message queues.

Pitfall: data loss (queue not persisted), retries (exponential backoff + DLQ), monitoring (queue depth).

### 328. Idempotency patterns?

Idempotency: repeating request produces same result. Crucial for distributed systems (network retries).

Techniques: Idempotent keys (client provides unique ID, server deduplicates). Correlation IDs (track requests end-to-end). Version numbers (if version unchanged, operation is idempotent).

Example:
```java
public OrderResponse createOrder(Order order, String idempotencyKey) {
  if (orderExists(idempotencyKey)) {
    return cachedResponse(idempotencyKey);
  }
  OrderResponse response = processOrder(order);
  cacheResponse(idempotencyKey, response);
  return response;
}
```

Pitfall: storage (cache idempotency keys for how long?). Typically 24 hours (payment retry window).

Testing: send duplicate request, verify same response.

### 329. Rate limiting patterns?

Rate limiting: restrict requests per time window. Prevent abuse, protect backend.

Algorithms: Token bucket (refill tokens at fixed rate, burst allowed). Sliding window (count requests in last X seconds, no burst). Leaky bucket (constant drain rate, smooths traffic).

Implementation (Spring Cloud):
```yaml
resilience4j:
  ratelimiter:
    instances:
      paymentService:
        limitRefreshPeriod: 1m
        limitForPeriod: 100
        timeoutDuration: 5s
```

API gateway (Nginx, Kong): enforce rate limits before app.

Pitfall: distributed systems (rate limit per instance vs. global). Use Redis to track global rate.

### 330. Kafka as message broker?

Kafka: distributed event streaming. Topics store events, consumers subscribe.

Key concepts: Topic (partitioned log of events). Partition (enables parallel consumption). Consumer group (multiple consumers share partitions, scale horizontally). Offset (position in partition; consumers track offset).

Guarantee: at-least-once (may reprocess), exactly-once (harder, using idempotency).

Example (Spring):
```java
@KafkaListener(topics = "orders", groupId = "order-processors")
public void consume(OrderEvent event) {
  processOrder(event.getOrder());
}

@Autowired private KafkaTemplate<String, OrderEvent> kafka;
public void publish(OrderEvent event) {
  kafka.send("orders", event);
}
```

Pitfall: offset management (commit too early = loss, commit late = reprocess). Use manual commit on success.

### 331. RabbitMQ vs. Kafka?

| Feature | RabbitMQ | Kafka |
|---------|----------|-------|
| **Use case** | Task queues, work distribution | Event streaming, event sourcing |
| **Semantics** | Push | Pull |
| **Scale** | Vertical | Horizontal |
| **Durability** | Ack-based | Offset-based |
| **Replay** | Limited | Full history |
| **Latency** | Low | Higher |

RabbitMQ good for: task queues, work distribution, TTL-based expiry.

Kafka good for: audit logs, event sourcing, real-time analytics, high throughput.

### 332. Kafka offset management?

Offset: position in partition. Consumers track offset; on restart, resume from offset.

Strategies: Auto-commit (offset committed periodically, default 5s. Risk: reprocess if crash before commit). Manual commit (commit after processing. Risk: long processing, broker thinks consumer dead).

Spring config:
```yaml
spring:
  kafka:
    consumer:
      auto-offset-reset: earliest
      enable-auto-commit: false
    listener:
      ack-mode: manual
```

Handler:
```java
@KafkaListener(topics = "orders")
public void consume(OrderEvent event, Acknowledgment ack) {
  try {
    processOrder(event);
    ack.acknowledge();
  } catch (Exception e) {
    // don't acknowledge; will retry
  }
}
```

Pitfall: slow processing (offset lag grows). Monitor consumer lag.

### 333. Event-driven architecture?

Event-driven: components communicate via events. Decoupled, scalable, real-time.

Pattern: producer publishes, consumers subscribe. Event bus (Kafka, RabbitMQ, SNS).

Example (microservices):
```
OrderService → OrderCreatedEvent → PaymentService
                                 → NotificationService
                                 → AnalyticsService
```

Benefits: scalability, flexibility (add consumer without modifying producer), real-time.

Pitfall: eventual consistency (consumer lag), event versioning, debugging (distributed tracing essential).

Tools: Spring Cloud Stream, AWS SNS/SQS.

### 334. Webhook vs. polling?

**Polling**: consumer periodically asks for updates (pull). Simple, frequent requests.

**Webhook**: provider calls consumer (push). Real-time, fewer requests.

Use polling for: unreliable consumers, low-frequency updates.

Use webhooks for: real-time requirements, reliable consumers (with retry).

Implementation (webhook):
```java
@PostMapping("/webhooks/payment-status")
public void handlePaymentStatusUpdate(@RequestBody PaymentStatusEvent event) {
  orderService.updatePaymentStatus(event);
}
```

Pitfall: webhook delivery failures. Implement retry (exponential backoff), dead letter queue.

### 335. Stream processing (Kafka Streams)?

Kafka Streams: library for building stream processing apps. Processes events in real-time.

Example: aggregate orders by minute.
```java
KStream<String, Order> orders = topology.stream("orders");
KTable<Windowed<String>, Long> orderCount = orders
  .groupByKey()
  .windowedBy(TimeWindows.of(Duration.ofMinutes(1)))
  .count();
```

Advantages: exactly-once semantics, local state stores, scalability.

Pitfall: stateful processing (maintains local state, distributed consensus hard). Use Flink/Spark for complex streams.

### 336. Monitoring with Prometheus?

Prometheus: time-series database for metrics. Scrapes endpoints, stores data, enables querying.

Setup: Instrument code (Micrometer). Expose /actuator/prometheus. Configure Prometheus to scrape. Query and alert.

Example metric:
```java
Counter.builder("orders.created")
  .description("Total orders created")
  .register(meterRegistry);
```

Query (PromQL):
```
rate(orders_created_total[5m])
```

Alert:
```yaml
alert: HighErrorRate
expr: rate(orders_failed_total[5m]) > 0.05
for: 5m
```

### 337. Distributed tracing with Jaeger?

Jaeger: traces requests across services. Correlates logs/metrics.

Setup: Spring Cloud Sleuth (extracts trace ID). Report to Jaeger (Brave client). Query Jaeger UI.

Trace includes: transaction ID, service name, span duration, errors.

Example: OrderService calls PaymentService → trace_id = abc123 → OrderService span: 10ms → PaymentService span: 5ms.

Benefits: identify bottlenecks, visualize request flow, causality.

Pitfall: sampling (trace all in dev; sample in prod). High-volume tracing expensive.

### 338. Spring Cloud Gateway?

API Gateway: entry point for all requests. Routes to services, enforces policies.

Configuration:
```yaml
spring:
  cloud:
    gateway:
      routes:
      - id: order-service
        uri: http://order-service:8080
        predicates:
        - Path=/orders/**
```

Custom filter:
```java
@Component
public class AuthFilter implements GlobalFilter {
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    String token = exchange.getRequest().getHeaders().getFirst("Authorization");
    if (!validateToken(token)) {
      return exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED).setComplete();
    }
    return chain.filter(exchange);
  }
}
```

Benefits: single entry point, centralized auth, rate limiting, request/response transformation.

Pitfall: single point of failure (use load balancer). Latency (additional hop).

### 339. Deployment automation (CI/CD)?

CI/CD: continuously integrate code, run tests, deploy to production.

Pipeline: Commit code → trigger build. Run tests (unit, integration, E2E). Build artifact (Docker image, JAR). Deploy to staging. Deploy to production (canary, rolling).

Tools: Jenkins, GitLab CI, GitHub Actions, ArgoCD.

Example (GitHub Actions):
```yaml
name: CI/CD
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - run: mvn test
```

Pitfall: slow tests. Parallelize, split into layers.

### 340. Canary deployments?

Canary: gradually roll out new version. Route small % traffic (5%) to new version, monitor metrics.

If error rate spikes → rollback. If stable → increase traffic.

Tools: Istio, Flagger (automates canary).

Configuration (Istio):
```yaml
VirtualService:
  name: payment-vs
  http:
  - match: []
    route:
    - destination:
        host: payment
        subset: v1
      weight: 95
    - destination:
        host: payment
        subset: v2
      weight: 5
```

Benefits: minimize impact, rollback easy, data-driven decisions.

### 341. Blue-green deployment?

Blue-green: two production environments (blue, green). Deploy to inactive (green), switch traffic. Quick rollback (switch back to blue).

Benefits: zero-downtime, easy rollback.

Trade-off: double infrastructure, data sync between environments.

### 342. Infrastructure as Code?

IaC: define infrastructure (servers, networks, databases) in code. Version controlled, reproducible.

Tools: Terraform, CloudFormation, Ansible.

Example (Terraform):
```hcl
resource "aws_instance" "web" {
  ami           = "ami-12345"
  instance_type = "t2.micro"
  tags = {
    Name = "web-server"
  }
}
```

Benefits: reproducibility, version control, automation.

Pitfall: state management, secrets in code. Use secret management (Vault, AWS Secrets Manager).

### 343. Containerization (Docker)?

Docker: package app + dependencies in container. Lightweight, portable.

Dockerfile:
```dockerfile
FROM openjdk:11-jdk
COPY target/app.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
```

Build and run:
```bash
docker build -t myapp:1.0 .
docker run -d -p 8080:8080 myapp:1.0
```

Benefits: consistency (same environment prod/dev), fast startup, scalability.

Pitfall: image bloat. Use multi-stage builds.

### 344. Kubernetes basics?

Kubernetes: orchestrate containers. Manages deployment, scaling, networking.

Core concepts: Pod (smallest deployable unit). Deployment (desired state: replicas, image). Service (stable IP, load balancing). ConfigMap (configuration). Secret (sensitive data).

Deployment YAML:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: payment-service
  template:
    spec:
      containers:
      - name: payment
        image: payment-service:1.0
        ports:
        - containerPort: 8080
```

Benefits: auto-scaling, self-healing, rolling updates, resource management.

Pitfall: complexity, operational overhead.

### 345. Helm charts?

Helm: package manager for Kubernetes. Templates reduce boilerplate.

Chart structure: templates, values.yaml, Chart.yaml.

Values YAML:
```yaml
replicaCount: 3
image:
  repository: payment-service
  tag: 1.0
```

Template (deployment.yaml):
```yaml
replicas: {{ .Values.replicaCount }}
image: {{ .Values.image.repository }}:{{ .Values.image.tag }}
```

Deploy:
```bash
helm install payment ./payment-chart -f values.yaml
```

Benefits: reusable, environments, versioning.

### 346. StatefulSets vs. Deployments?

**Deployments**: stateless apps. Pods interchangeable, no unique identity. Good for web services.

**StatefulSets**: stateful apps. Each pod has stable identity (name, storage). Good for databases, message queues.

Example (StatefulSet):
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mysql
spec:
  serviceName: mysql
  replicas: 3
  volumeClaimTemplates:
  - metadata:
      name: mysql-storage
    spec:
      accessModes: [ReadWriteOnce]
      resources:
        requests:
          storage: 10Gi
```

Benefits: stable identity, persistent storage, ordered startup/shutdown.

Pitfall: complexity (managing replicas, storage).

### 347. Horizontal Pod Autoscaling?

HPA: auto-scale pods based on metrics (CPU, memory, custom).

Configuration:
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: payment-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: payment-service
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

Behavior: if avg CPU > 70%, add pod (up to 10). If < 30%, remove pod (min 2).

Pitfall: metrics must be exposed (Prometheus), HPA checks every 15s (lag).

### 348. PersistentVolumes in Kubernetes?

PersistentVolume: storage independent of pod lifecycle. Pod crashes, data persists.

Types: local storage, NFS, AWS EBS, Google Persistent Disk.

Claim (PersistentVolumeClaim):
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data-pvc
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

Pod mount:
```yaml
containers:
- name: app
  volumeMounts:
  - name: data
    mountPath: /data
volumes:
- name: data
  persistentVolumeClaim:
    claimName: data-pvc
```

Pitfall: storage provisioning, performance varies.

### 349. ConfigMaps and Secrets?

**ConfigMap**: non-sensitive configuration (feature flags, DB URL).

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  app.properties: |
    debug=false
    feature.payments.v2=true
```

**Secret**: sensitive data (passwords, API keys). Base64 encoded; use external secret manager.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-secret
type: Opaque
data:
  password: Y2hhbmdlaXQ=
```

Pitfall: Secrets not encrypted at rest by default. Use external secret management (Vault, AWS Secrets Manager).

### 350. Service mesh observability?

Service mesh (Istio) provides built-in observability: metrics, logs, traces without code changes.

Metrics (Prometheus):
```
istio_request_total{destination_workload="payment-service", response_code="200"}
```

Integration stack: Istio → Prometheus (scrape metrics). Jaeger (distributed tracing). Grafana (visualize metrics). Kiali (observe service mesh).

Kiali: shows services, traffic flow, latency, error rates. Visual representation of mesh.

Pitfall: observability overhead (sidecar proxies increase resource usage, latency).

Benefit: service behavior without code instrumentation.

---

## Q351–Q400: Advanced Spring & Microservices Continued

### Q351: What is integration testing in the Spring context? Provide an example.

Integration testing validates component interactions (service, repository, controller). @SpringBootTest loads full application context.

Example:
```java
@SpringBootTest
@AutoConfigureTestDatabase(replace = REPLACE_ANY)
public class OrderServiceIntegrationTest {
  @Autowired OrderService orderService;
  @Autowired OrderRepository orderRepository;
  
  @Test
  public void testCreateOrder() {
    Order order = orderService.createOrder(new Order(userId=1, amount=100));
    Order saved = orderRepository.findById(order.getId());
    assertThat(saved.getAmount()).isEqualTo(100);
  }
}
```

Trade-off: slow (full context), but catches real interactions. Better than unit tests alone for confidence.

Pitfall: sharing test data state; use @DirtiesContext to reset context.

---

### Q352: What does Spring Actuator provide? Name key endpoints.

Spring Actuator exposes operational endpoints for monitoring production applications.

Key endpoints:
- /actuator/health: application status (UP, DOWN)
- /actuator/metrics: Micrometer metrics (jvm.memory, http.requests)
- /actuator/prometheus: Prometheus-format metrics
- /actuator/env: environment properties
- /actuator/beans: registered beans
- /actuator/threaddump: thread info

Example:
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,metrics,prometheus
  metrics:
    export:
      prometheus:
        enabled: true
```

Benefit: production visibility without code changes.

Pitfall: exposing all endpoints is security risk; restrict access via Spring Security.

---

### Q353: What are advanced Spring Data JPA features?

Custom @Query, projections, lazy loading, N+1 prevention, specification pattern.

Example (custom query):
```java
@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {
  @Query("SELECT o FROM Order o WHERE o.userId = ?1 AND o.status = 'COMPLETED'")
  List<Order> findCompletedOrdersByUser(Long userId);
}
```

Projection (fetch only columns):
```java
public interface OrderProjection {
  Long getId();
  String getStatus();
}

@Query("SELECT o FROM Order o WHERE o.userId = ?1")
List<OrderProjection> findOrdersProjection(Long userId);
```

N+1 prevention via @EntityGraph:
```java
@EntityGraph(attributePaths = {"items", "customer"})
List<Order> findAll();
```

Benefit: control over queries, reduced data transfer, better performance.

Pitfall: lazy loading causes N+1 queries if not using @EntityGraph.

---

### Q354: Explain Spring WebFlux and reactive programming.

Spring WebFlux provides non-blocking, asynchronous reactive framework using Mono (0-1 element) and Flux (0-* elements).

Example:
```java
@RestController
@RequestMapping("/orders")
public class OrderController {
  @Autowired OrderService orderService;
  
  @GetMapping("/{id}")
  public Mono<Order> getOrder(@PathVariable Long id) {
    return orderService.findOrder(id);
  }
  
  @GetMapping
  public Flux<Order> getAllOrders() {
    return orderService.findAllOrders();
  }
}

@Service
public class OrderService {
  @Autowired OrderRepository orderRepository;
  
  public Mono<Order> findOrder(Long id) {
    return orderRepository.findById(id);
  }
  
  public Flux<Order> findAllOrders() {
    return orderRepository.findAll();
  }
}
```

Backpressure: consumer signals demand, producer adapts (subscribeOn/publishOn).

Trade-off: higher throughput, but steeper learning curve, harder debugging.

Pitfall: mixing blocking code in reactive chains (use blockingGet() only in tests).

---

### Q355: What is Spring Security's OAuth2/OpenID Connect integration?

OAuth2 enables secure delegated access. OpenID Connect adds identity layer.

Example (OAuth2 client configuration):
```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: <id>
            client-secret: <secret>
            scope: openid,profile,email
        provider:
          google:
            issuer-uri: https://accounts.google.com
```

Authorization flow:
1. User clicks "Login with Google"
2. Browser redirects to Google authorization endpoint
3. User consents
4. Google redirects back with authorization code
5. Backend exchanges code for access token (server-to-server)
6. Backend uses access token to fetch user info
7. Create session/JWT, redirect to app

Custom AuthenticationProvider:
```java
@Component
public class CustomAuthProvider implements AuthenticationProvider {
  public Authentication authenticate(Authentication auth) {
    String username = auth.getName();
    String password = (String) auth.getCredentials();
    if (isValidCredential(username, password)) {
      return new UsernamePasswordAuthenticationToken(username, null, getAuthorities(username));
    }
    throw new BadCredentialsException("Invalid");
  }
  
  public boolean supports(Class<?> auth) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(auth);
  }
}
```

Benefit: SSO, reduced password management, user consent.

Pitfall: token revocation complexity, refresh token management, PKCE for mobile.

---

### Q356: How do you version REST APIs?

Versioning strategies: URL path (/v1/orders), query parameter (?version=1), header (Accept-Version), content negotiation.

URL path (most explicit):
```java
@RestController
@RequestMapping("/v1/orders")
public class OrderControllerV1 {
  @GetMapping("/{id}")
  public ResponseEntity<OrderV1Dto> getOrder(@PathVariable Long id) {
    return ResponseEntity.ok(new OrderV1Dto(...));
  }
}

@RestController
@RequestMapping("/v2/orders")
public class OrderControllerV2 {
  @GetMapping("/{id}")
  public ResponseEntity<OrderV2Dto> getOrder(@PathVariable Long id) {
    return ResponseEntity.ok(new OrderV2Dto(...));
  }
}
```

Header versioning:
```java
@RestController
@RequestMapping("/orders")
public class OrderController {
  @GetMapping(value = "/{id}", headers = "Accept-Version=1")
  public ResponseEntity<OrderV1Dto> getOrderV1(@PathVariable Long id) { ... }
  
  @GetMapping(value = "/{id}", headers = "Accept-Version=2")
  public ResponseEntity<OrderV2Dto> getOrderV2(@PathVariable Long id) { ... }
}
```

Trade-off: URL path is explicit (cache-friendly), header is subtle (harder to test in browser).

Pitfall: breaking changes require client migration strategy.

---

### Q357: Describe error handling and recovery patterns.

Global exception handler via @RestControllerAdvice:
```java
@RestControllerAdvice
public class GlobalExceptionHandler {
  @ExceptionHandler(EntityNotFoundException.class)
  public ResponseEntity<ErrorResponse> handleNotFound(EntityNotFoundException e) {
    return ResponseEntity.status(404).body(new ErrorResponse(e.getMessage()));
  }
  
  @ExceptionHandler(DataIntegrityViolationException.class)
  public ResponseEntity<ErrorResponse> handleConstraint(DataIntegrityViolationException e) {
    return ResponseEntity.status(409).body(new ErrorResponse("Conflict"));
  }
  
  @ExceptionHandler(Exception.class)
  public ResponseEntity<ErrorResponse> handleGeneric(Exception e) {
    return ResponseEntity.status(500).body(new ErrorResponse("Internal Server Error"));
  }
}
```

Recovery patterns:
- Retry with exponential backoff (circuit breaker fallback)
- Graceful degradation (cached data if service unavailable)
- Circuit breaker (fail fast, prevent cascading failure)
- Compensation (rollback in saga)

Benefit: consistent error responses, resilience.

Pitfall: catching Exception too broadly masks real issues; log all errors.

---

### Q358: What performance tuning strategies improve Spring applications?

Database optimization:
- Index frequently queried columns (composite index on user_id + status)
- Connection pooling: HikariCP (minimumPoolSize=5, maximumPoolSize=20, idle timeout)
- Query optimization: fetch only needed columns, use LIMIT, avoid N+1

Caching:
- @Cacheable on method: store result
- @CacheEvict on update: invalidate
- Cache-aside pattern: miss → fetch → store

Example:
```java
@Service
public class OrderService {
  @Cacheable(value = "orders", key = "#userId", unless = "#result == null")
  public Order getOrder(Long userId) {
    return orderRepository.findById(userId);
  }
  
  @CacheEvict(value = "orders", key = "#order.userId")
  public void updateOrder(Order order) {
    orderRepository.save(order);
  }
}
```

Thread pool tuning: TaskExecutor with corePoolSize, maxPoolSize, queue capacity.

JVM tuning: -Xmx2g (heap), -XX:+UseG1GC (garbage collector).

Trade-off: optimization adds complexity; profile before optimizing.

Pitfall: caching stale data; use TTL (time-to-live) and invalidation strategies.

---

### Q359: What are logging best practices in distributed systems?

Structured logging (JSON) enables machine parsing:
```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "level": "ERROR",
  "service": "order-service",
  "traceId": "abc123def456",
  "userId": "user-789",
  "message": "Failed to process payment",
  "error": "PaymentGatewayTimeout"
}
```

Implement with Logback + Logstash:
```xml
<appender name="JSON" class="net.logstash.logback.appender.LogstashTcpSocketAppender">
  <destination>localhost:5000</destination>
</appender>
```

Correlation IDs propagate across services:
```java
@Component
public class CorrelationIdFilter implements Filter {
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {
    String correlationId = UUID.randomUUID().toString();
    MDC.put("traceId", correlationId);
    chain.doFilter(req, res);
    MDC.remove("traceId");
  }
}
```

Pass correlation ID in headers (X-Trace-Id) to downstream services.

Benefit: tracing requests across services, debugging distributed issues.

Pitfall: logging sensitive data (passwords, credit cards); use sanitization.

---

### Q360: Explain Spring Cloud Config and externalized configuration.

Spring Cloud Config centralizes configuration in Git repository, enabling dynamic refresh.

Server setup:
```properties
spring.cloud.config.server.git.uri=https://github.com/config-repo
```

Client setup:
```yaml
spring:
  application:
    name: order-service
  cloud:
    config:
      uri: http://config-server:8888
```

Configuration file: order-service.properties in Git repo:
```properties
database.url=jdbc:mysql://localhost/orders
database.username=root
feature.payment=true
```

Access in code:
```java
@Component
public class OrderConfig {
  @Value("${database.url}")
  private String databaseUrl;
  
  @Value("${feature.payment}")
  private boolean paymentFeatureEnabled;
}
```

Dynamic refresh via @RefreshScope:
```java
@Component
@RefreshScope
public class FeatureToggle {
  @Value("${feature.payment}")
  private boolean paymentEnabled;
  
  public boolean isPaymentEnabled() {
    return paymentEnabled; // reflects updated value after /actuator/refresh
  }
}
```

Trigger refresh:
```bash
curl -X POST http://localhost:8080/actuator/refresh
```

Benefit: configuration changes without redeploy.

Pitfall: eventual consistency; some instances may be out of sync during refresh.

---

### Q361: What is Spring Batch and when do you use it?

Spring Batch processes large volumes of data in chunks. ItemReader → ItemProcessor → ItemWriter.

Example (bulk import):
```java
@Configuration
@EnableBatchProcessing
public class BatchConfig {
  @Bean
  public Job importOrdersJob(JobRepository jobRepository, PlatformTransactionManager tm) {
    return new JobBuilder("importOrders", jobRepository)
      .start(orderStep(jobRepository, tm))
      .build();
  }
  
  @Bean
  public Step orderStep(JobRepository jobRepository, PlatformTransactionManager tm) {
    return new StepBuilder("orderStep", jobRepository)
      .<OrderCSVRecord, Order> chunk(100) // 100 items per transaction
      .reader(new FlatFileItemReaderBuilder<OrderCSVRecord>()
        .name("csvReader")
        .resource(new ClassPathResource("orders.csv"))
        .delimited()
        .names("orderId", "userId", "amount")
        .targetType(OrderCSVRecord.class)
        .build())
      .processor(new ItemProcessor<OrderCSVRecord, Order>() {
        public Order process(OrderCSVRecord csv) {
          return new Order(csv.getOrderId(), csv.getUserId(), csv.getAmount());
        }
      })
      .writer(new RepositoryItemWriter<Order>() {
        {
          setRepository(orderRepository);
          setMethodName("save");
        }
      })
      .transactionManager(tm)
      .build();
  }
}
```

Benefits: transaction management, chunking (memory efficient), restart capability on failure.

Pitfall: stateful processors across chunks; use StepExecution to maintain state.

---

### Q362: Explain gRPC and Protocol Buffers.

gRPC (Google Remote Procedure Call) is high-performance RPC framework using binary serialization (Protocol Buffers).

Define service in .proto file:
```proto
syntax = "proto3";

package order;

message Order {
  int64 id = 1;
  int64 user_id = 2;
  double amount = 3;
  string status = 4;
}

service OrderService {
  rpc GetOrder(GetOrderRequest) returns (Order);
  rpc CreateOrder(Order) returns (Order);
}

message GetOrderRequest {
  int64 order_id = 1;
}
```

Server implementation:
```java
@GrpcService
public class OrderServiceImpl extends OrderServiceGrpc.OrderServiceImplBase {
  @Autowired OrderRepository orderRepository;
  
  @Override
  public void getOrder(GetOrderRequest request, StreamObserver<Order> response) {
    Order order = orderRepository.findById(request.getOrderId());
    response.onNext(order);
    response.onCompleted();
  }
}
```

Client:
```java
@Component
public class OrderClient {
  private OrderServiceGrpc.OrderServiceBlockingStub stub;
  
  public OrderClient(ManagedChannel channel) {
    this.stub = OrderServiceGrpc.newBlockingStub(channel);
  }
  
  public Order getOrder(Long orderId) {
    return stub.getOrder(GetOrderRequest.newBuilder().setOrderId(orderId).build());
  }
}
```

Benefits: binary format (small payload), strongly typed schema, HTTP/2 multiplexing, bidirectional streaming.

Pitfall: less human-readable than JSON; requires schema definition and code generation.

---

### Q363: What are message patterns in distributed systems?

Pub-Sub (asynchronous, decoupled):
- Producer publishes event to topic
- Multiple consumers subscribe independently
- Example: OrderCreatedEvent → Invoice Service, Notification Service, Analytics

Request-Reply (synchronous RPC):
- Producer sends request, waits for response
- Tight coupling, but immediate feedback
- Example: Payment Service calls Credit Card Gateway

Event Sourcing (immutable event log):
- All state changes stored as events
- Replay events to restore state
- Example: Order → OrderCreatedEvent, OrderPaidEvent, OrderShippedEvent

Saga (distributed transaction):
- Long-running process with compensating transactions
- Example: CreateOrder → Reserve Inventory → Process Payment (if fail, compensate each)

Benefit: scalability (Pub-Sub, async), consistency (Request-Reply), auditability (Event Sourcing).

Pitfall: eventual consistency requires handling duplicate processing, out-of-order events.

---

### Q364: How does Spring Scheduling work?

@Scheduled runs tasks at fixed intervals or cron expressions.

Example:
```java
@Component
public class OrderCleanupTask {
  @Autowired OrderRepository orderRepository;
  
  @Scheduled(fixedRate = 60000) // every 60 seconds
  public void cleanupExpiredOrders() {
    orderRepository.deleteExpiredOrders();
  }
  
  @Scheduled(cron = "0 0 2 * * ?") // daily at 2 AM
  public void dailyReport() {
    System.out.println("Sending daily report");
  }
}
```

Enable scheduling:
```java
@SpringBootApplication
@EnableScheduling
public class Application {
  public static void main(String[] args) {
    SpringApplication.run(Application.class);
  }
}
```

Distributed scheduling (use database lock to prevent duplicate execution across instances):
```java
@Scheduled(fixedRate = 60000)
public void scheduledTask() {
  // Acquire lock in database before executing
  if (lockService.acquireLock("cleanup-task")) {
    try {
      cleanupOrders();
    } finally {
      lockService.releaseLock("cleanup-task");
    }
  }
}
```

Benefit: simple periodic tasks without external tools.

Pitfall: blocking task delays subsequent scheduled tasks; use async with @Async.

---

### Q365: Explain multi-tenancy in SaaS applications.

Multi-tenancy: single application instance serves multiple customers (tenants), with isolated data.

Approaches:

1. Database per tenant (strong isolation):
   ```java
   @Component
   public class TenantContextFilter implements Filter {
     public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {
       String tenantId = req.getParameter("tenant_id");
       TenantContext.setCurrentTenant(tenantId);
       chain.doFilter(req, res);
       TenantContext.clear();
     }
   }
   
   @Configuration
   public class DataSourceConfig {
     @Bean
     public DataSource dataSource(TenantResolver tenantResolver) {
       return new AbstractRoutingDataSource() {
         protected Object determineCurrentLookupKey() {
           return TenantContext.getCurrentTenant();
         }
       };
     }
   }
   ```

2. Schema per tenant (shared infrastructure, isolated schema).

3. Row-level security (shared table, filter by tenant_id via Hibernate filters).

Trade-off: database isolation (complex ops), row-level security (simpler ops, risk of data leakage).

Pitfall: forgetting to filter by tenant_id in queries.

---

### Q366: What are database migrations (Flyway/Liquibase)?

Flyway automates database schema versioning and migrations.

Migration file: src/main/resources/db/migration/V1__Create_order_table.sql
```sql
CREATE TABLE orders (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT NOT NULL,
  amount DECIMAL(10, 2),
  status VARCHAR(50),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

V2__Add_payment_method.sql:
```sql
ALTER TABLE orders ADD COLUMN payment_method VARCHAR(50);
```

Configuration:
```yaml
spring:
  flyway:
    enabled: true
    locations: classpath:db/migration
    baselineOnMigrate: true
```

Flyway auto-runs on startup, tracking executed migrations in flyway_schema_history table.

Benefits: version control, repeatable deployments, rollback capability (create reverse migration).

Pitfall: complex migrations require testing; avoid irreversible operations (like DROP COLUMN without backup).

---

### Q367: What are Spring testing annotations?

@SpringBootTest: full context (slow, comprehensive).
@WebMvcTest: web layer only (fast, for controllers).
@DataJpaTest: JPA layer only (fast, for repositories).
@MockBean: replace bean with mock (inject mock via constructor).
@SpyBean: partial mock (call real methods unless overridden).

Example:
```java
@WebMvcTest(OrderController.class)
public class OrderControllerTest {
  @Autowired MockMvc mockMvc;
  @MockBean OrderService orderService;
  
  @Test
  public void testGetOrder() throws Exception {
    when(orderService.getOrder(1L)).thenReturn(new Order(1, 100));
    mockMvc.perform(get("/orders/1"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.amount").value(100));
  }
}

@DataJpaTest
public class OrderRepositoryTest {
  @Autowired OrderRepository orderRepository;
  
  @Test
  public void testFindByUserId() {
    Order order = new Order(userId=1, amount=50);
    orderRepository.save(order);
    List<Order> found = orderRepository.findByUserId(1);
    assertThat(found).hasSize(1);
  }
}
```

Benefit: fast feedback, isolated testing.

Pitfall: @MockBean requires full context; use @WebMvcTest for speed.

---

### Q368: What are conditional bean creation strategies?

@ConditionalOnProperty, @ConditionalOnClass, @ConditionalOnMissingBean enable feature flags.

Example:
```java
@Configuration
public class FeatureConfig {
  @Bean
  @ConditionalOnProperty(name = "feature.payment.enabled", havingValue = "true")
  public PaymentService paymentService() {
    return new RealPaymentService();
  }
  
  @Bean
  @ConditionalOnProperty(name = "feature.payment.enabled", havingValue = "false", matchIfMissing = true)
  public PaymentService noOpPaymentService() {
    return new NoOpPaymentService();
  }
}
```

@ConditionalOnClass (bean only if class on classpath):
```java
@ConditionalOnClass(name = "com.stripe.Stripe")
@Bean
public StripePaymentProvider stripeProvider() {
  return new StripePaymentProvider();
}
```

Benefit: feature toggles, environment-specific beans without code changes.

Pitfall: multiple conditional beans compete; ensure exactly one matches.

---

### Q369: What REST client patterns exist?

RestTemplate (blocking, synchronous):
```java
@Service
public class PaymentClient {
  @Autowired RestTemplate restTemplate;
  
  public PaymentResponse charge(Order order) throws RestClientException {
    String url = "http://payment-service/charge";
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    
    PaymentRequest request = new PaymentRequest(order.getId(), order.getAmount());
    HttpEntity<PaymentRequest> entity = new HttpEntity<>(request, headers);
    
    ResponseEntity<PaymentResponse> response = restTemplate.exchange(
      url, HttpMethod.POST, entity, PaymentResponse.class);
    return response.getBody();
  }
}
```

WebClient (non-blocking, reactive):
```java
@Service
public class PaymentClientReactive {
  @Autowired WebClient webClient;
  
  public Mono<PaymentResponse> chargeAsync(Order order) {
    return webClient.post()
      .uri("http://payment-service/charge")
      .contentType(MediaType.APPLICATION_JSON)
      .bodyValue(new PaymentRequest(order.getId(), order.getAmount()))
      .retrieve()
      .bodyToMono(PaymentResponse.class);
  }
}
```

Resilience:
```java
@Service
public class ResilientPaymentClient {
  @Autowired WebClient webClient;
  
  @CircuitBreaker(name = "paymentService")
  public Mono<PaymentResponse> chargeWithCircuitBreaker(Order order) {
    return webClient.post()
      .uri("http://payment-service/charge")
      .bodyValue(order)
      .retrieve()
      .onStatus(is4xxClientError(), res -> Mono.error(new ClientException()))
      .onStatus(is5xxServerError(), res -> Mono.error(new ServerException()))
      .bodyToMono(PaymentResponse.class)
      .timeout(Duration.ofSeconds(5));
  }
}
```

Trade-off: RestTemplate is synchronous (simpler), WebClient is reactive (higher throughput).

Pitfall: timeout configuration essential; default infinite wait causes resource exhaustion.

---

### Q370: What are Stream API and lambda expression best practices?

Stream API enables declarative data processing. Lambdas provide functional syntax.

Example:
```java
List<Order> orders = orderRepository.findAll();

// Filter, map, collect
List<Double> amounts = orders.stream()
  .filter(o -> o.getStatus().equals("COMPLETED"))
  .map(Order::getAmount)
  .collect(Collectors.toList());

// Group by
Map<String, List<Order>> byUser = orders.stream()
  .collect(Collectors.groupingBy(Order::getUserId));

// Parallel processing (caution: overhead for small datasets)
long total = orders.parallelStream()
  .filter(o -> o.getAmount() > 100)
  .count();
```

Best practices:
- Use method references (Order::getAmount) over lambdas for readability
- Avoid stateful lambdas (use state variables carefully in parallel streams)
- Intermediate operations are lazy; terminal operation triggers evaluation

Pitfall: parallel streams on small lists slower than sequential due to thread overhead.

---

### Q371: What are caching strategies?

Cache-aside: miss → fetch → store
```java
@Service
public class OrderService {
  @Cacheable(value = "orders", key = "#id")
  public Order getOrder(Long id) {
    return orderRepository.findById(id);
  }
}
```

Write-through: update DB and cache synchronously
```java
@Service
public class OrderService {
  public void updateOrder(Order order) {
    orderRepository.save(order);
    cache.put(order.getId(), order);
  }
}
```

Write-behind: update cache, async DB (risk: data loss if crash before DB update)
```java
@Service
public class OrderService {
  public void updateOrder(Order order) {
    cache.put(order.getId(), order);
    asyncExecutor.execute(() -> orderRepository.save(order));
  }
}
```

Distributed cache (Redis):
```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

```yaml
spring:
  redis:
    host: localhost
    port: 6379
```

Trade-off: cache-aside (simple, miss on first request), write-through (immediate consistency, slower writes), write-behind (fast writes, eventual consistency).

Pitfall: cache invalidation (stale data); use TTL and explicit eviction.

---

### Q372: What are timeout and circuit breaker patterns?

Timeout: abort operation after X seconds, prevent hanging.

Circuit Breaker: track failures, fail-fast when threshold exceeded.

Example (Resilience4j):
```java
@Service
public class PaymentService {
  private CircuitBreaker circuitBreaker;
  private Retry retry;
  private TimeLimiter timeLimiter;
  
  public PaymentService() {
    circuitBreaker = CircuitBreaker.of("paymentService", CircuitBreakerConfig.custom()
      .slidingWindowSize(10) // track last 10 calls
      .failureThreshold(50) // 50% failure rate opens circuit
      .waitDurationInOpenState(Duration.ofSeconds(30))
      .build());
    
    retry = Retry.of("paymentService", RetryConfig.custom()
      .maxAttempts(3)
      .waitDuration(Duration.ofSeconds(1))
      .build());
    
    timeLimiter = TimeLimiter.of(TimeLimiterConfig.custom()
      .timeoutDuration(Duration.ofSeconds(5))
      .build());
  }
  
  public Payment charge(Order order) {
    Supplier<Payment> supplier = () -> paymentGateway.charge(order);
    Supplier<Payment> timed = timeLimiter.decorateSupplier(supplier);
    Supplier<Payment> retried = retry.decorateSupplier(timed);
    Supplier<Payment> circuitBreakerDecorated = circuitBreaker.decorateSupplier(retried);
    
    return circuitBreakerDecorated.get(); // may throw exception if circuit open
  }
}
```

States:
- CLOSED: happy path, count failures
- OPEN: too many failures, reject all calls (fast-fail)
- HALF_OPEN: test if service recovered, limited calls allowed

Benefit: cascading failure prevention, graceful degradation.

Pitfall: timeout too short causes false positives; too long defeats purpose.

---

### Q373: What is JSON serialization customization?

Use @JsonProperty, @JsonIgnore, custom JsonSerializer.

Example:
```java
public class Order {
  @JsonProperty("order_id") // maps to JSON field "order_id"
  private Long id;
  
  @JsonIgnore
  private String internalNotes;
  
  @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
  private LocalDateTime createdAt;
}

// Custom serializer
public class OrderSerializer extends StdSerializer<Order> {
  public void serialize(Order order, JsonGenerator jgen, SerializerProvider provider) {
    jgen.writeStartObject();
    jgen.writeNumberField("id", order.getId());
    jgen.writeStringField("status", order.getStatus().toUpperCase());
    jgen.writeEndObject();
  }
}

// Register
@Configuration
public class JacksonConfig {
  @Bean
  SimpleModule customModule() {
    SimpleModule module = new SimpleModule();
    module.addSerializer(Order.class, new OrderSerializer());
    return module;
  }
}
```

Benefit: API contract control, backward compatibility.

Pitfall: over-customization complicates maintenance.

---

### Q374: What is Lombok and what annotations does it provide?

Lombok auto-generates boilerplate code via annotations.

@Data: @Getter, @Setter, @ToString, @EqualsAndHashCode, @RequiredArgsConstructor
```java
@Data
public class Order {
  private Long id;
  private String status;
  // generates getters, setters, toString(), equals(), hashCode(), constructor(id, status)
}
```

@Builder: fluent object creation
```java
Order order = Order.builder()
  .id(1L)
  .status("PENDING")
  .build();
```

@Slf4j: inject SLF4J logger
```java
@Service
@Slf4j
public class OrderService {
  public void process(Order order) {
    log.info("Processing order: {}", order.getId());
  }
}
```

@AllArgsConstructor, @NoArgsConstructor: constructors.

Benefit: less boilerplate code.

Pitfall: IDE support required (annotation processing); generated code not visible in editor.

---

### Q375: What are Optional best practices?

Optional wraps nullable values, preventing NullPointerException.

Example:
```java
Optional<Order> orderOpt = orderRepository.findById(1L);

// Good: explicit handling
Order order = orderOpt.orElseThrow(() -> new EntityNotFoundException());

// Good: use ifPresent
orderOpt.ifPresent(o -> log.info("Found order: {}", o.getId()));

// Good: map
String status = orderOpt.map(Order::getStatus).orElse("UNKNOWN");

// Bad: avoid get() without isPresent() check
Order order = orderOpt.get(); // throws NoSuchElementException if empty

// Bad: avoid Optional in parameters
public void process(Optional<Order> order) { ... } // use nullable instead
```

Best practices:
- Use Optional for method returns, not parameters
- Use map/flatMap for transformations
- Use orElse/orElseGet for defaults
- Use filter to narrow values

Benefit: explicit null handling, compiler-checkable.

Pitfall: overusing Optional (in parameters, fields) adds noise.

---

### Q376: What are dependency injection best practices?

Constructor injection (preferred, testable, immutable):
```java
@Service
public class OrderService {
  private final OrderRepository orderRepository;
  private final PaymentService paymentService;
  
  public OrderService(OrderRepository orderRepository, PaymentService paymentService) {
    this.orderRepository = orderRepository;
    this.paymentService = paymentService;
  }
}
```

Field injection (discouraged, not testable):
```java
@Service
public class OrderService {
  @Autowired OrderRepository orderRepository; // discouraged
}
```

Setter injection (less preferred):
```java
@Service
public class OrderService {
  private OrderRepository orderRepository;
  
  @Autowired
  public void setOrderRepository(OrderRepository orderRepository) {
    this.orderRepository = orderRepository;
  }
}
```

Best practices:
- Use constructor injection for required dependencies
- Mark fields final to prevent reassignment
- Avoid circular dependencies (A → B → A)

Pitfall: constructor injection with 10+ parameters (sign of God object); refactor.

---

### Q377: What is Bean Validation API?

Bean Validation provides annotations (@NotNull, @Email, etc.) and custom validators.

Example:
```java
public class Order {
  @NotNull(message = "ID required")
  private Long id;
  
  @Positive(message = "Amount must be positive")
  private double amount;
  
  @Pattern(regexp = "PENDING|COMPLETED|CANCELLED")
  private String status;
}

@RestController
@RequestMapping("/orders")
public class OrderController {
  @PostMapping
  public ResponseEntity<Order> createOrder(@Valid @RequestBody Order order) {
    // validation happens automatically; 400 Bad Request if invalid
    return ResponseEntity.ok(orderService.create(order));
  }
}
```

Custom validator:
```java
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = CurrencyValidator.class)
public @interface ValidCurrency {
  String message() default "Invalid currency";
  Class<?>[] groups() default {};
  Class<? extends Payload>[] payload() default {};
}

public class CurrencyValidator implements ConstraintValidator<ValidCurrency, String> {
  public boolean isValid(String value, ConstraintValidatorContext context) {
    return value == null || Arrays.asList("USD", "EUR", "GBP").contains(value);
  }
}
```

Benefit: standardized validation, reduced boilerplate.

Pitfall: validation messages not user-friendly; customize error responses.

---

### Q378: What is connection pooling (HikariCP)?

Connection pooling reuses database connections, reducing overhead.

Example (HikariCP configuration):
```yaml
spring:
  datasource:
    hikari:
      minimumIdle: 5 # idle connections kept alive
      maximumPoolSize: 20 # max concurrent connections
      idleTimeout: 600000 # 10 minutes before closing idle connection
      maxLifetime: 1800000 # 30 minutes max connection lifetime
      connectionTimeout: 30000 # 30 seconds to acquire connection
```

How it works:
1. Create connection pool (size: 5–20) on startup
2. Request connection from pool (fast)
3. Use connection
4. Return to pool (not close)
5. Reuse on next request

Benefit: reduced latency (no connection creation), resource efficiency.

Pitfall: connections leak if not returned; use try-with-resources or Spring's template classes.

---

### Q379: What are memory management and garbage collection strategies?

Heap sizing determines GC performance.

Example:
```bash
java -Xms1g -Xmx4g -XX:+UseG1GC application.jar
# -Xms: initial heap (1GB)
# -Xmx: max heap (4GB)
# G1GC: generational garbage collector
```

Garbage collectors:
- Serial GC: single thread, suitable for small applications
- Parallel GC: multiple threads, suitable for batch processing
- G1GC (default): low-pause, suitable for large heaps and low-latency requirements
- ZGC: ultra-low pause (< 1ms), for large heaps (experimental)

Monitor GC:
```bash
java -XX:+PrintGCDetails -XX:+PrintGCDateStamps -Xloggc:/tmp/gc.log application.jar
```

Memory leak prevention:
- Avoid unclosed resources (streams, connections)
- Unbounded caches (use Caffeine with size limits)
- Static collections holding references

Benefit: optimized performance, reduced latency.

Pitfall: GC pause time increases with large heaps; balance heap size and frequency.

---

### Q380: What are design patterns in microservices?

API Gateway: single entry point (routing, auth, rate limiting)
Service Locator: discover services dynamically
Circuit Breaker: fail-fast on unavailable service
Saga: distributed transaction
CQRS: separate read/write models
Event Sourcing: immutable event log
Bulkhead: thread pool isolation per resource

Example (API Gateway pattern):
```java
@RestController
@RequestMapping("/api")
public class ApiGateway {
  @GetMapping("/orders/{id}")
  public ResponseEntity<Order> getOrder(@PathVariable Long id) {
    return orderServiceClient.getOrder(id);
  }
  
  @GetMapping("/payments/{id}")
  public ResponseEntity<Payment> getPayment(@PathVariable Long id) {
    return paymentServiceClient.getPayment(id);
  }
}
```

Benefit: decoupling, cross-cutting concern management.

Pitfall: gateway becomes bottleneck; ensure scalability.

---

### Q381: What are cost optimization strategies?

Reserved instances: pre-pay for capacity, save 40–60% vs. on-demand
Spot instances: unused capacity at discount, suitable for batch jobs
Auto-scaling: scale down during off-peak hours
Resource tagging: track costs per team/project
Database: use read replicas only when needed, storage optimization

Example (ECS/K8s cost optimization):
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: order-service
spec:
  containers:
  - name: order-service
    image: order-service:latest
    resources:
      requests:
        memory: "256Mi" # guaranteed minimum
        cpu: "250m"
      limits:
        memory: "512Mi" # hard limit before eviction
        cpu: "500m"
```

Benefit: reduced cloud spending.

Pitfall: over-aggressive cost optimization causes performance degradation.

---

### Q382: What are bulk operations and batch insert patterns?

Batch insert reduces database round-trips.

Example (JPA batch insert):
```java
@Service
public class OrderService {
  @Autowired OrderRepository orderRepository;
  
  public void importOrders(List<Order> orders) {
    int batchSize = 1000;
    for (int i = 0; i < orders.size(); i += batchSize) {
      List<Order> batch = orders.subList(i, Math.min(i + batchSize, orders.size()));
      orderRepository.saveAll(batch);
      // flush to database every 1000 records
    }
  }
}
```

Enable batch settings in properties:
```yaml
spring:
  jpa:
    hibernate:
      jdbc:
        batch_size: 1000
        fetch_size: 1000
      order_inserts: true
      order_updates: true
```

Benefit: 10–50x performance improvement for bulk operations.

Pitfall: memory usage increases with large batches; tune batch size.

---

### Q383: What is OpenTelemetry integration?

OpenTelemetry provides unified observability API (traces, metrics, logs).

Example (Spring Boot with OpenTelemetry):
```xml
<dependency>
  <groupId>io.opentelemetry.instrumentation</groupId>
  <artifactId>opentelemetry-spring-boot-starter</artifactId>
  <version>0.35.0</version>
</dependency>
```

Configuration:
```yaml
otel:
  exporter:
    otlp:
      endpoint: http://jaeger:4317 # OTEL collector
  sdk:
    disabled: false
```

Custom instrumentation:
```java
@Component
public class OrderServiceObservable {
  private static final Tracer tracer = GlobalOpenTelemetry.getTracer("order-service");
  
  @Autowired OrderRepository orderRepository;
  
  public Order getOrder(Long id) {
    Span span = tracer.spanBuilder("getOrder").setAttribute("order.id", id).startSpan();
    try (Scope scope = span.makeCurrent()) {
      return orderRepository.findById(id);
    } finally {
      span.end();
    }
  }
}
```

Benefit: vendor-neutral observability, standardized instrumentation.

Pitfall: overhead; use sampling for high-throughput services.

---

### Q384: How do you mock external services in tests?

WireMock (HTTP mocking):
```java
@SpringBootTest
public class OrderServiceTest {
  @RegisterExtension
  static WireMockExtension wireMock = WireMockExtension.newInstance()
    .options(wireMockConfig().port(8899))
    .build();
  
  @BeforeEach
  public void setup() {
    wireMock.stubFor(get(urlEqualTo("/payments/charge"))
      .willReturn(aResponse()
        .withStatus(200)
        .withBody("{\"status\": \"SUCCESS\"}")));
  }
  
  @Test
  public void testChargePayment() {
    Payment payment = paymentClient.charge(order);
    assertThat(payment.getStatus()).isEqualTo("SUCCESS");
  }
}
```

Testcontainers (container-based mocking):
```java
@SpringBootTest
public class OrderServiceIntegrationTest {
  @Container
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(DockerImageName.parse("postgres:latest"));
  
  @Test
  public void testOrderPersistence() {
    Order order = new Order(1, 100);
    orderRepository.save(order);
    Order found = orderRepository.findById(1);
    assertThat(found.getAmount()).isEqualTo(100);
  }
}
```

Benefit: realistic mocking, integration testing without full services.

Pitfall: containers add test startup overhead; use judiciously.

---

### Q385: What is backpressure in reactive streams?

Backpressure: consumer signals demand, producer adapts production rate.

Example (Flux with limited subscription):
```java
Flux<Integer> numbers = Flux.range(1, 1000);

numbers
  .subscribeOn(Schedulers.parallel())
  .publishOn(Schedulers.boundedElastic()) // consumer slower than producer
  .subscribe(
    item -> {
      Thread.sleep(1000); // slow consumer
      log.info("Received: {}", item);
    },
    error -> log.error("Error", error),
    () -> log.info("Complete")
  );
// Backpressure: producer slows down to match consumer's pace
```

Without backpressure (unbounded Flux):
- Fast producer floods slow consumer
- Memory exhaustion (buffering all items)

With backpressure:
- Consumer requests N items
- Producer emits only N items
- Memory stays bounded

Benefit: resource efficiency, prevents OutOfMemoryError.

Pitfall: backpressure not automatic; both sides must implement reactive contract.

---

### Q386: Spring Cloud Hystrix vs. Resilience4j comparison.

Hystrix (legacy):
- Integrated with Spring Cloud (easy setup)
- Thread pool isolation (bulkhead pattern)
- Circuit breaker, retry, timeout

Resilience4j (modern, recommended):
- Lightweight, functional programming style
- Decorator pattern (composable)
- Metrics integration (Micrometer)
- No thread pool overhead (functional approach)

Example migration (Hystrix → Resilience4j):
```java
// Hystrix (deprecated)
@HystrixCommand(fallbackMethod = "fallback", commandProperties = {
  @HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "5000")
})
public Payment charge(Order order) { ... }

// Resilience4j (modern)
@CircuitBreaker(name = "paymentService")
@Retry(name = "paymentService")
@Timeout(name = "paymentService")
public Payment charge(Order order) { ... }
```

Recommendation: use Resilience4j for new projects.

Pitfall: Hystrix in maintenance mode; migrate existing code.

---

### Q387: What is Spring Cloud Eureka (service discovery)?

Eureka enables dynamic service discovery (service registers heartbeat, clients discover registry).

Server setup:
```java
@SpringBootApplication
@EnableEurekaServer
public class EurekaServer {
  public static void main(String[] args) {
    SpringApplication.run(EurekaServer.class);
  }
}
```

Client registration:
```yaml
spring:
  application:
    name: order-service
eureka:
  client:
    serviceUrl:
      defaultZone: http://eureka-server:8761/eureka
  instance:
    instanceId: ${spring.application.name}:${spring.application.instance-id:${random.value}}
```

Access registered services:
```java
@Service
public class PaymentClient {
  @Autowired RestTemplate restTemplate;
  
  public Payment charge(Order order) {
    // RestTemplate auto-resolves payment-service via Eureka
    return restTemplate.getForObject("http://payment-service/charge", Payment.class);
  }
}
```

Benefit: dynamic service registry (scale services without code changes).

Pitfall: Eureka eventually consistent (heartbeat misses → delayed removal).

---

### Q388: What is Vault for secrets management?

Vault centrally manages secrets (API keys, database passwords, certificates).

Example (Vault integration):
```yaml
spring:
  cloud:
    vault:
      host: vault.example.com
      port: 8200
      token: s.xxxxxxx
      kv:
        enabled: true
        backend: secret
        version: 2
```

Retrieve secrets:
```java
@Service
public class PaymentGatewayConfig {
  @Value("${vault.gateway.api-key}")
  private String apiKey; // injected from Vault
  
  public PaymentGateway createGateway() {
    return new PaymentGateway(apiKey);
  }
}
```

Vault stores:
```json
{
  "data": {
    "api_key": "sk_live_xxxxx",
    "api_secret": "sk_secret_xxxxx"
  }
}
```

Benefit: centralized secret management, rotation without code changes.

Pitfall: Vault availability critical; ensure HA setup.

---

### Q389: How does rate limiting work at API Gateway level?

API Gateway (Spring Cloud Gateway) rate limits using token bucket algorithm.

Example:
```yaml
spring:
  cloud:
    gateway:
      routes:
      - id: order-service
        uri: http://order-service:8080
        predicates:
        - Path=/orders/**
        filters:
        - name: RequestRateLimiter
          args:
            redis-rate-limiter:
              replenishRate: 10 # 10 requests per second
              burstCapacity: 20 # burst to 20 requests
```

How it works:
1. Each user has token bucket (capacity: 20 tokens)
2. Bucket refills at 10 tokens/second
3. Each request consumes 1 token
4. If bucket empty, request rejected (429 Too Many Requests)

Custom rate limiter (key-resolver):
```java
@Configuration
public class GatewayConfig {
  @Bean
  public KeyResolver userKeyResolver() {
    return exchange -> Mono.just(
      exchange.getRequest().getHeaders().getFirst("X-User-Id")
    );
  }
}
```

Benefit: prevents abuse, ensures fair usage.

Pitfall: rate limit too strict causes legitimate client rejection; too lenient defeats purpose.

---

### Q390: What is content negotiation in REST APIs?

Content negotiation: server returns response format (JSON, XML) based on client request.

Accept header: request format
```
Accept: application/json
Accept: application/xml
Accept: application/json;charset=UTF-8
```

Spring handles content negotiation:
```java
@RestController
@RequestMapping("/orders")
public class OrderController {
  @GetMapping("/{id}", produces = { MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE })
  public Order getOrder(@PathVariable Long id) {
    return orderService.getOrder(id);
  }
}
```

Client requests JSON:
```bash
curl -H "Accept: application/json" http://localhost:8080/orders/1
Response: { "id": 1, "status": "PENDING" }
```

Client requests XML:
```bash
curl -H "Accept: application/xml" http://localhost:8080/orders/1
Response: <Order><id>1</id><status>PENDING</status></Order>
```

Benefit: single API serves multiple formats.

Pitfall: maintenance burden (support multiple formats); JSON-only preferable.

---

### Q391: What are HTTPS and certificate pinning?

HTTPS (TLS) encrypts communication. Certificate pinning validates server identity.

Enable HTTPS:
```properties
server.ssl.key-store=classpath:keystore.jks
server.ssl.key-store-password=password
server.ssl.key-store-type=JKS
server.ssl.key-alias=tomcat
```

Certificate pinning (prevent MITM attacks):
```java
@Configuration
public class RestClientPinning {
  @Bean
  public RestTemplate restTemplate() {
    // Pin certificate hash (validate server cert matches expected hash)
    X509Certificate cert = loadCertificate();
    String expectedSha256 = "abc123def456...";
    
    HttpClient httpClient = HttpClients.custom()
      .setSSLContext(createCustomSSLContext(expectedSha256))
      .build();
    
    return new RestTemplate(new HttpComponentsClientHttpRequestFactory(httpClient));
  }
}
```

Benefit: prevents MITM (man-in-the-middle) attacks.

Pitfall: certificate pinning limits flexibility; renewal requires code update.

---

### Q392: What is graceful degradation in microservices?

Graceful degradation: reduce functionality rather than fail completely.

Example (payment service unavailable):
```java
@Service
public class OrderService {
  @Autowired PaymentClient paymentClient;
  @Autowired CacheService cache;
  
  @CircuitBreaker(name = "paymentService", fallbackMethod = "degradedPaymentFlow")
  public Order createOrder(CreateOrderRequest request) {
    String paymentId = paymentClient.initiatePayment(request.getAmount());
    return new Order(request, paymentId);
  }
  
  public Order degradedPaymentFlow(CreateOrderRequest request, Exception e) {
    // Payment service down; create order with PENDING_PAYMENT status
    // Manual payment processing later
    Order order = new Order(request, null);
    order.setStatus("PENDING_PAYMENT");
    cache.save("pending_orders", order.getId, order);
    return order;
  }
}
```

Strategies:
- Serve cached data if DB unavailable
- Disable non-critical features
- Queue requests for later processing
- Return partial data

Benefit: resilience to service failures.

Pitfall: degraded mode complexity; ensure consistent state.

---

### Q393: What is polyglot persistence?

Polyglot persistence: use different databases for different use cases.

Example architecture:
- User service: PostgreSQL (relational, ACID)
- Product catalog: Elasticsearch (full-text search)
- Session cache: Redis (fast, in-memory)
- Time-series metrics: InfluxDB (optimized for metrics)
- Graph relationships: Neo4j (graph queries)

Implementation:
```java
@Service
public class OrderService {
  @Autowired OrderRepository orderRepository; // PostgreSQL
  @Autowired ProductSearchClient productSearch; // Elasticsearch
  @Autowired CacheService cache; // Redis
  
  public Order createOrder(CreateOrderRequest request) {
    // Persist order in PostgreSQL
    Order order = orderRepository.save(new Order(request));
    
    // Cache order in Redis
    cache.set("order:" + order.getId(), order, Duration.ofHours(1));
    
    // Index in Elasticsearch for analytics
    searchService.index("orders", order);
    
    return order;
  }
}
```

Trade-off: flexibility (right tool for job), but operational complexity (manage multiple databases).

Pitfall: data consistency across databases; use event-driven sync.

---

### Q394: What are feature toggles with gradual rollout?

Feature toggle: flag controls feature behavior without code change. Gradual rollout: enable for % of users.

Example (using FF4j library):
```xml
<dependency>
  <groupId>org.ff4j</groupId>
  <artifactId>ff4j-spring-boot-starter</artifactId>
</dependency>
```

Define toggles:
```yaml
ff4j:
  features:
    new-payment-gateway:
      enabled: true
      description: "Use Stripe instead of legacy gateway"
      permissions: []
```

Usage:
```java
@Service
public class PaymentService {
  @Autowired FF4j ff4j;
  
  public Payment charge(Order order) {
    if (ff4j.check("new-payment-gateway")) {
      return stripeGateway.charge(order);
    } else {
      return legacyGateway.charge(order);
    }
  }
}
```

Gradual rollout (canary):
```java
public boolean isNewPaymentEnabled(String userId) {
  // enable for 10% of users (hash-based)
  return userId.hashCode() % 100 < 10;
}
```

Benefit: zero-downtime feature deployment, A/B testing.

Pitfall: feature flag debt (accumulate stale toggles); regular cleanup.

---

### Q395: What are correlation IDs and request tracking?

Correlation ID: unique identifier per request, propagates across services for tracing.

Implementation:
```java
@Component
public class CorrelationIdFilter implements Filter {
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
    String correlationId = request.getHeader("X-Trace-Id");
    if (correlationId == null) {
      correlationId = UUID.randomUUID().toString();
    }
    
    MDC.put("correlationId", correlationId); // Mapped Diagnostic Context
    response.addHeader("X-Trace-Id", correlationId);
    
    try {
      chain.doFilter(request, response);
    } finally {
      MDC.remove("correlationId");
    }
  }
}
```

Pass to downstream services:
```java
@Service
public class PaymentClient {
  public Payment charge(Order order) {
    String correlationId = MDC.get("correlationId");
    
    return webClient.post()
      .uri("http://payment-service/charge")
      .header("X-Trace-Id", correlationId) // propagate ID
      .bodyValue(order)
      .retrieve()
      .bodyToMono(Payment.class)
      .block();
  }
}
```

Logging (correlation ID in logs):
```log
2024-01-15T10:30:45Z [traceId=abc123] OrderService: Creating order
2024-01-15T10:30:46Z [traceId=abc123] PaymentService: Charging payment
2024-01-15T10:30:47Z [traceId=abc123] NotificationService: Sending confirmation
```

Benefit: end-to-end request tracing, debugging distributed issues.

Pitfall: ensure all services propagate correlation ID; async operations lose context.

---

### Q396: What is database query profiling?

Query profiling identifies slow queries, optimization opportunities.

Enable query logging:
```yaml
logging:
  level:
    org.hibernate.SQL: DEBUG
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE
```

Output:
```sql
SELECT order0_.id AS id1_0_, order0_.amount AS amount2_0_, order0_.status AS status3_0_
FROM orders order0_
WHERE order0_.user_id=?
```

Use EXPLAIN ANALYZE (PostgreSQL):
```sql
EXPLAIN ANALYZE SELECT * FROM orders WHERE user_id = 1;
Seq Scan on orders (cost=0.00..35.50 rows=1)
Filter: (user_id = 1)
```

Add index:
```sql
CREATE INDEX idx_orders_user_id ON orders(user_id);
```

Re-run EXPLAIN:
```sql
Index Scan using idx_orders_user_id (cost=0.28..8.29 rows=1)
```

Tools: Spring DataSource Spy, Hibernate Statistics, p6spy (JDBC proxy).

Benefit: performance optimization insights.

Pitfall: profiling overhead; disable in production or use sampling.

---

### Q397: What is Spring Cloud LoadBalancer?

Spring Cloud LoadBalancer provides client-side load balancing across service instances.

Configuration:
```yaml
spring:
  cloud:
    loadbalancer:
      ribbon:
        enabled: false
      nacos: # or eureka
        enabled: true
```

Usage with RestTemplate:
```java
@Configuration
public class RestTemplateConfig {
  @Bean
  @LoadBalanced
  public RestTemplate restTemplate() {
    return new RestTemplate();
  }
}

@Service
public class PaymentClient {
  @Autowired
  @LoadBalanced
  RestTemplate restTemplate;
  
  public Payment charge(Order order) {
    // Automatically load-balanced across payment-service instances
    return restTemplate.postForObject("http://payment-service/charge", order, Payment.class);
  }
}
```

Load balancing strategies:
- Round-robin (default)
- Random
- Least request
- Weighted round-robin

Benefit: client-side balancing (no gateway overhead), service discovery integration.

Pitfall: clients must implement load balancing; server-side gateway simpler.

---

### Q398: What are concurrent request handling and async/await patterns?

Async processing improves throughput by handling multiple requests concurrently.

@Async:
```java
@Service
public class OrderService {
  @Async
  public void processOrderAsync(Order order) {
    // Runs in thread pool, doesn't block caller
    paymentService.charge(order);
    notificationService.sendConfirmation(order);
  }
}

@RestController
public class OrderController {
  @PostMapping("/orders")
  public ResponseEntity<Order> createOrder(@RequestBody Order order) {
    Order created = orderService.createOrder(order);
    orderService.processOrderAsync(created); // async background processing
    return ResponseEntity.ok(created);
  }
}
```

CompletableFuture (composition):
```java
public CompletableFuture<Order> createOrderAsync(Order order) {
  return CompletableFuture.supplyAsync(() -> orderService.create(order))
    .thenCompose(createdOrder -> paymentService.chargeAsync(createdOrder))
    .thenCompose(paidOrder -> notificationService.sendAsync(paidOrder));
}
```

Reactive (WebFlux):
```java
@GetMapping("/orders/{id}")
public Mono<Order> getOrderReactive(@PathVariable Long id) {
  return orderRepository.findById(id); // non-blocking
}
```

Benefit: higher concurrency, better throughput.

Pitfall: async introduces complexity (error handling, thread context loss); use judiciously.

---

### Q399: What is idempotency in API design?

Idempotency: repeated requests produce same result (safe to retry).

Implementation (deduplication key):
```java
@RestController
@RequestMapping("/orders")
public class OrderController {
  @PostMapping
  public ResponseEntity<Order> createOrder(
    @RequestHeader("Idempotency-Key") String idempotencyKey,
    @RequestBody CreateOrderRequest request) {
    
    // Check if request already processed
    Order existingOrder = orderService.findByIdempotencyKey(idempotencyKey);
    if (existingOrder != null) {
      return ResponseEntity.ok(existingOrder); // idempotent response
    }
    
    // Process new request
    Order order = orderService.createOrder(idempotencyKey, request);
    return ResponseEntity.status(201).body(order);
  }
}
```

Store idempotency key with result:
```java
@Entity
public class Order {
  @Id private Long id;
  @Column(unique = true) private String idempotencyKey; // unique constraint
  private String status;
}
```

HTTP methods:
- GET: idempotent (side-effect free)
- PUT: idempotent (replace resource)
- DELETE: idempotent (idempotent key prevents duplicate deletion)
- POST: NOT idempotent (unless deduplication implemented)

Benefit: safe retries (network failures, timeouts), exactly-once semantics.

Pitfall: storing idempotency keys forever (cost); use TTL.

---

### Q400: What is user-based rate limiting?

User-based rate limiting restricts requests per user (not global).

Example (Redis-backed):
```java
@Component
public class UserRateLimiter {
  @Autowired StringRedisTemplate redisTemplate;
  
  public boolean isAllowed(String userId, int limit) {
    String key = "rate-limit:" + userId;
    
    // Increment user requests
    Long count = redisTemplate.opsForValue().increment(key);
    
    // Set expiration (1 minute window)
    if (count == 1) {
      redisTemplate.expire(key, Duration.ofMinutes(1));
    }
    
    return count <= limit;
  }
}

@RestController
@RequestMapping("/orders")
public class OrderController {
  @Autowired UserRateLimiter rateLimiter;
  
  @GetMapping
  public ResponseEntity<?> listOrders(@RequestHeader("X-User-Id") String userId) {
    if (!rateLimiter.isAllowed(userId, 100)) { // 100 requests per minute
      return ResponseEntity.status(429).body("Rate limit exceeded");
    }
    return ResponseEntity.ok(orderService.list());
  }
}
```

Token bucket per user (differentiated limits):
```java
public boolean isAllowed(String userId, int tokensPerMinute) {
  String key = "tokens:" + userId;
  long tokens = redisTemplate.opsForValue().increment(key, -1);
  
  if (tokens < 0) {
    redisTemplate.opsForValue().increment(key, 1); // refund token
    return false;
  }
  
  if (tokens == tokensPerMinute - 1) { // first request
    redisTemplate.expire(key, Duration.ofMinutes(1));
  }
  
  return true;
}
```

Benefit: fair usage per user, prevents abuse by individual users.

Pitfall: distributed rate limiting complex (clock skew, race conditions); use mature libraries.

---

## Q401–Q450: Advanced Security, Compliance & Performance

### Q401: What is zero-trust security in microservices?

Zero-trust: assume all requests are untrusted; verify every request regardless of source.

Principles:
- Never trust, always verify (authentication + authorization on every request)
- Least privilege (minimal permissions, deny by default)
- Assume breach (encrypt data at rest & in transit)
- Continuous monitoring

Implementation:
```java
@Configuration
@EnableWebSecurity
public class ZeroTrustSecurityConfig {
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
      .authorizeHttpRequests(auth -> auth
        .anyRequest().authenticated()) // all requests must be authenticated
      .oauth2ResourceServer(oauth2 -> oauth2
        .jwt(jwt -> jwt.decoder(jwtDecoder())));
    
    return http.build();
  }
  
  @Bean
  public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withPublicKey(loadPublicKey()).build();
  }
}
```

mTLS (mutual TLS) between services:
```yaml
spring:
  cloud:
    gateway:
      routes:
      - id: order-service
        uri: https://order-service:8443
        predicates:
        - Path=/orders/**
        metadata:
          ssl:
            verify-hostname: true
            enabled: true
```

Benefit: defense-in-depth, breach containment.

Pitfall: complexity increases; requires sophisticated identity infrastructure.

---

### Q402: What is secrets rotation and how to implement it?

Secrets rotation: regularly change secrets (API keys, passwords) to minimize breach impact.

Example (Vault-based rotation):
```java
@Component
public class SecretsRotationManager {
  @Autowired VaultTemplate vaultTemplate;
  
  @Scheduled(fixedRate = 2592000000L) // rotate monthly
  public void rotateApiKeys() {
    String currentKey = vaultTemplate.read("secret/data/payment/api-key").getData().get("api_key");
    String newKey = generateNewApiKey();
    
    // Update in Vault
    vaultTemplate.write("secret/data/payment/api-key", Collections.singletonMap("api_key", newKey));
    
    // Notify services to reload
    eventPublisher.publishEvent(new SecretsRotatedEvent("payment-api-key"));
    
    // Deactivate old key (grace period for in-flight requests using old key)
    Thread.sleep(5000);
    paymentGateway.deactivateApiKey(currentKey);
  }
}

@Component
public class SecretsRefreshListener {
  @EventListener
  public void onSecretsRotated(SecretsRotatedEvent event) {
    // Refresh beans that depend on secrets
    applicationContext.getBean(PaymentService.class).reloadSecrets();
  }
}
```

Rotation strategies:
- Time-based: rotate monthly
- Event-based: rotate on deployment, breach detection
- Risk-based: rotate for high-risk secrets more frequently

Benefit: limits blast radius of compromised secret.

Pitfall: rotation window (old + new keys) must be managed; not atomic across distributed systems.

---

### Q403: What is GDPR compliance in software systems?

GDPR (General Data Protection Regulation) requirements:

Right to access: users can request data about them
```java
@PostMapping("/users/{id}/data-export")
public ResponseEntity<InputStream> exportUserData(@PathVariable String userId) {
  User user = userService.findById(userId);
  InputStream export = userService.exportDataAsJson(user);
  return ResponseEntity.ok()
    .header("Content-Disposition", "attachment; filename=user-data.json")
    .body(export);
}
```

Right to be forgotten: deletion on request
```java
@DeleteMapping("/users/{id}")
public ResponseEntity<?> deleteUser(@PathVariable String userId) {
  userService.anonymizeUser(userId); // remove identifiable data
  return ResponseEntity.noContent().build();
}
```

Data minimization: collect only necessary data
```java
public class UserRegistration {
  @NotNull private String email; // collect
  @Email private String recoveryEmail; // optional, not required
  private String phoneNumber; // unnecessary, don't collect
}
```

Consent tracking:
```java
@Entity
public class ConsentLog {
  @Id private UUID id;
  private String userId;
  private String consentType; // "marketing", "analytics", "cookies"
  private boolean granted;
  private LocalDateTime timestamp;
}
```

Benefit: regulatory compliance, user trust.

Pitfall: GDPR enforcement (EU fines 4% of revenue); implement properly from start.

---

### Q404: What is PCI-DSS compliance for payment systems?

PCI-DSS (Payment Card Industry Data Security Standard) protects cardholder data.

Requirements:
- Never log/store card data (card number, CVV)
- Tokenize cards (replace with token, store token)
- Encrypt data in transit & at rest
- Regular security testing (penetration tests)

Implementation (tokenized payment):
```java
@Service
public class PaymentService {
  @Autowired StripeGateway stripeGateway;
  
  public Payment processPayment(Order order, CardDetails card) {
    // Tokenize card (Stripe handles card data, returns token)
    String cardToken = stripeGateway.createToken(card);
    
    // Never store or log card details
    // Store only card token
    CardTokenEntity cardToken = new CardTokenEntity(cardToken, order.getUserId());
    cardTokenRepository.save(cardToken);
    
    // Charge using token
    Payment payment = stripeGateway.charge(order.getAmount(), cardToken);
    return payment;
  }
}
```

Encryption (TDE - Transparent Data Encryption):
```sql
ALTER TABLE cards ENCRYPTION BY 'AES_256';
```

Benefit: PCI-DSS compliance, reduces liability (payment processor handles cardholder data).

Pitfall: compliance is continuous; regular audits & penetration testing required.

---

### Q405: What is audit logging and how to implement it?

Audit logging records who did what, when, for compliance & forensics.

Example:
```java
@Entity
public class AuditLog {
  @Id private UUID id;
  private String userId;
  private String action; // "CREATE_ORDER", "UPDATE_USER", "DELETE_PAYMENT"
  private String entityType; // "Order", "User"
  private Long entityId;
  private String oldValue;
  private String newValue;
  private LocalDateTime timestamp;
  private String ipAddress;
}

@Component
public class AuditLoggingAspect {
  @Autowired AuditLogRepository auditLogRepository;
  
  @Around("@annotation(com.example.Audited)")
  public Object auditMethod(ProceedingJoinPoint joinPoint) throws Throwable {
    String userId = SecurityContextHolder.getContext().getAuthentication().getName();
    String action = ((MethodSignature) joinPoint.getSignature()).getMethod().getName();
    String ipAddress = RequestContextHolder.getRequestAttributes().getRemoteUser();
    
    Object result = joinPoint.proceed();
    
    AuditLog log = new AuditLog(userId, action, ipAddress, LocalDateTime.now());
    auditLogRepository.save(log);
    
    return result;
  }
}

@Service
public class OrderService {
  @Audited
  public Order createOrder(CreateOrderRequest request) {
    // recorded in audit log
    return orderRepository.save(new Order(request));
  }
}
```

Immutable audit logs (prevent tampering):
```java
@Entity
@Table(name = "audit_logs")
public class AuditLog {
  @CreationTimestamp
  @Column(updatable = false, nullable = false)
  private LocalDateTime createdAt; // cannot be updated
  
  @Version
  private Long version; // detects tampering attempts
}
```

Benefit: compliance (SOX, HIPAA), forensics, accountability.

Pitfall: audit logs themselves can become attack target; secure separately (separate DB, encryption).

---

### Q406: What is performance profiling and benchmarking?

Performance profiling identifies bottlenecks using tools like JProfiler, YourKit, Async Profiler.

Example (Async Profiler):
```bash
# Profile CPU
asyncProfiler -d 30 -f /tmp/profile.html jps | grep Application

# Profile memory
asyncProfiler -e alloc -d 30 jps | grep Application
```

Output: flame graph showing CPU/memory distribution across stack traces.

Benchmarking with JMH (Java Microbenchmark Harness):
```xml
<dependency>
  <groupId>org.openjdk.jmh</groupId>
  <artifactId>jmh-core</artifactId>
  <version>1.35</version>
</dependency>
```

```java
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(1)
@Warmups(3)
@Measurement(iterations = 10)
public class OrderServiceBenchmark {
  @Benchmark
  public Order createOrder() {
    Order order = new Order(1L, 100.0, "PENDING");
    return order;
  }
  
  @Benchmark
  public List<Order> filterOrders() {
    List<Order> orders = generateOrders(1000);
    return orders.stream()
      .filter(o -> o.getAmount() > 50)
      .collect(Collectors.toList());
  }
}
```

Run: `java -jar benchmarks.jar -i 10 -wi 3 -f 1`

Benefit: data-driven optimization, regression detection.

Pitfall: microbenchmarks can be misleading (JIT optimizations, warmup); profile real workloads.

---

### Q407: What are Spring Integration module capabilities?

Spring Integration provides messaging & enterprise integration patterns (EIP).

Example (polling channels):
```java
@Configuration
@EnableIntegration
public class IntegrationConfig {
  @Bean
  public IntegrationFlow fileIntegrationFlow() {
    return IntegrationFlows
      .from(Files.inboundAdapter(new File("/orders"))
        .preventDuplicates(true)
        .filter(f -> f.getName().endsWith(".csv")), c -> c.poller(Pollers.fixedRate(5000)))
      .transform(msg -> parseOrderFile((File) msg.getPayload()))
      .handle((payload, headers) -> {
        orderService.processOrders((List<Order>) payload);
        return null;
      })
      .get();
  }
}
```

Channels:
- Direct channel: synchronous
- Queue channel: async, message buffering
- Publish-subscribe channel: broadcast to multiple handlers

Error handling:
```java
@Bean
public IntegrationFlow errorHandlingFlow() {
  return IntegrationFlows
    .from("inputChannel")
    .errorChannel(c -> c.errorHandler(errorHandler()))
    .route(new OrderRouter())
    .get();
}

@Bean
public ErrorHandler errorHandler() {
  return (exception, message) -> {
    log.error("Error processing message: {}", message, exception);
    errorRepository.save(new ErrorLog(exception.getMessage(), message));
  };
}
```

Benefit: decouples components, handles asynchronous flows.

Pitfall: complexity increases; use only when needed (Kafka/RabbitMQ may be simpler).

---

### Q408: What are advanced caching strategies (write-through, write-behind, refresh-ahead)?

Write-through: update DB and cache synchronously
```java
public void createOrder(Order order) {
  orderRepository.save(order); // 1. write to DB
  cache.put(order.getId(), order); // 2. write to cache
  // if cache write fails, rollback DB write
}
```

Write-behind: write to cache immediately, async DB update
```java
public void createOrder(Order order) {
  cache.put(order.getId(), order); // 1. immediate response
  asyncExecutor.submit(() -> {
    try {
      orderRepository.save(order); // 2. async DB write
    } catch (Exception e) {
      cache.evict(order.getId()); // 3. rollback cache if DB write fails
      throw e;
    }
  });
}
```

Refresh-ahead: proactively refresh cache before expiration
```java
@Component
public class CacheRefreshScheduler {
  @Scheduled(fixedRate = 60000) // every minute
  public void refreshHotData() {
    List<Order> hotOrders = orderRepository.findByStatus("SHIPPING"); // frequently accessed
    hotOrders.forEach(order -> cache.put("order:" + order.getId(), order, Duration.ofHours(1)));
  }
}
```

Cache hierarchy (L1, L2):
- L1 (local): in-process (Caffeine), fast, limited size
- L2 (distributed): Redis, slower, large capacity

Implementation:
```java
@Service
public class OrderService {
  @Autowired Caffeine<String, Order> l1Cache;
  @Autowired RedisTemplate redisTemplate;
  
  public Order getOrder(Long id) {
    String key = "order:" + id;
    
    // Check L1
    Order order = l1Cache.getIfPresent(key);
    if (order != null) return order;
    
    // Check L2
    order = (Order) redisTemplate.opsForValue().get(key);
    if (order != null) {
      l1Cache.put(key, order);
      return order;
    }
    
    // Fetch from DB
    order = orderRepository.findById(id);
    l1Cache.put(key, order);
    redisTemplate.opsForValue().set(key, order, Duration.ofHours(1));
    return order;
  }
}
```

Trade-off: write-through (consistency, slower), write-behind (fast, eventual consistency, data loss risk).

Pitfall: cache invalidation complexity (stale data, inconsistency).

---

### Q409: What is ML/AI model integration in Spring applications?

Machine learning model serving: train model, deploy, serve predictions via API.

Example (Spring Cloud Stream + TensorFlow):
```xml
<dependency>
  <groupId>org.tensorflow</groupId>
  <artifactId>tensorflow-core-api</artifactId>
  <version>0.4.0</version>
</dependency>
```

```java
@Service
public class RecommendationService {
  private SavedModelBundle model; // TensorFlow model
  
  @PostConstruct
  public void loadModel() {
    model = SavedModelBundle.load("/path/to/recommendation_model", "serve");
  }
  
  public List<Product> getRecommendations(Long userId) {
    // Fetch user features
    float[] userFeatures = userFeatureService.getFeatures(userId);
    
    // Run inference
    Operand<?> input = tf.constant(userFeatures);
    ConcreteFunction<?> function = model.function("serving_default");
    Output<?> predictions = function.call(input).get(0);
    
    // Convert predictions to products
    float[][] scores = predictions.asRawTensor().data().asFloats().reshape(new long[]{1, -1})[0];
    return productRepository.findByIdsWithScores(scores);
  }
}

@RestController
@RequestMapping("/recommendations")
public class RecommendationController {
  @Autowired RecommendationService recommendationService;
  
  @GetMapping("/users/{userId}")
  public ResponseEntity<List<Product>> getRecommendations(@PathVariable Long userId) {
    return ResponseEntity.ok(recommendationService.getRecommendations(userId));
  }
}
```

Model versioning:
```yaml
ml:
  models:
    recommendation:
      current: v2
      versions:
        v1: /models/recommendation_v1
        v2: /models/recommendation_v2
```

A/B testing (canary):
```java
public List<Product> getRecommendations(Long userId) {
  if (userId % 100 < 10) { // 10% canary
    return modelV2.predict(userId);
  } else {
    return modelV1.predict(userId);
  }
}
```

Benefit: personalization, predictive capabilities.

Pitfall: model complexity (latency, inference cost); model maintenance (retraining, drift).

---

### Q410: What is internationalization (i18n) and localization (l10n)?

i18n: application supports multiple languages/regions. l10n: translation for specific locale.

Example (Spring message resources):
```
messages_en.properties:
greeting=Hello, {0}!
order.created=Order created successfully

messages_fr.properties:
greeting=Bonjour, {0}!
order.created=Commande créée avec succès

messages_es.properties:
greeting=Hola, {0}!
order.created=Orden creada con éxito
```

Java config:
```java
@Configuration
public class I18nConfig {
  @Bean
  public LocaleResolver localeResolver() {
    SessionLocaleResolver resolver = new SessionLocaleResolver();
    resolver.setDefaultLocale(Locale.ENGLISH);
    return resolver;
  }
  
  @Bean
  public MessageSource messageSource() {
    ResourceBundleMessageSource source = new ResourceBundleMessageSource();
    source.setBasename("messages");
    source.setDefaultEncoding("UTF-8");
    return source;
  }
}
```

Usage in controllers:
```java
@RestController
public class OrderController {
  @Autowired MessageSource messageSource;
  @Autowired LocaleResolver localeResolver;
  
  @PostMapping("/orders")
  public ResponseEntity<?> createOrder(@RequestBody Order order, HttpServletRequest request) {
    Order created = orderService.create(order);
    Locale locale = localeResolver.resolveLocale(request);
    String message = messageSource.getMessage("order.created", null, locale);
    return ResponseEntity.ok(Map.of("order", created, "message", message));
  }
}
```

Date/number formatting (locale-aware):
```java
@RestController
public class ReportController {
  @GetMapping("/report")
  public Map<String, String> generateReport(@RequestHeader("Accept-Language") String lang) {
    Locale locale = Locale.forLanguageTag(lang);
    DecimalFormat df = (DecimalFormat) NumberFormat.getInstance(locale);
    
    return Map.of(
      "price", df.format(99.99),
      "date", SimpleDateFormat.getDateInstance(SimpleDateFormat.LONG, locale).format(new Date())
    );
  }
}
```

Translation workflow:
1. Extract message keys from code
2. Send to translators (crowdsourcing, professional)
3. Integrate translated properties files
4. Test for layout issues (some languages longer)

Benefit: global market reach.

Pitfall: incomplete translations (fallback to default), layout issues (CJK languages take more space).

---

### Q411: What are SLO, SLI, SLA in reliability engineering?

SLI (Service Level Indicator): measurable metric (99.9% uptime, p99 latency < 100ms)
SLO (Service Level Objective): target SLI (we will maintain 99.9% uptime)
SLA (Service Level Agreement): contractual promise (if not met, refund)

Example:
```
SLI: availability = (successful requests / total requests) * 100
SLO: maintain 99.95% availability (error budget: 0.05% per month)
SLA: 99.95% availability guaranteed; if not met, customer gets 10% refund
```

Error budget: how much downtime allowed within SLO
```
Monthly error budget = (1 - SLO) * hours_per_month
Example: (1 - 0.9995) * 730 hours = 0.36 hours (22 minutes downtime allowed)
```

Implementation:
```java
@Component
public class SLIMonitor {
  @Autowired MeterRegistry meterRegistry;
  
  public void recordRequest(boolean success, long durationMs) {
    meterRegistry.timer("http.request.duration").record(durationMs, TimeUnit.MILLISECONDS);
    meterRegistry.counter("http.request", "status", success ? "success" : "failure").increment();
  }
  
  public double calculateAvailability() {
    Double successCount = meterRegistry.find("http.request")
      .tag("status", "success")
      .counters()
      .stream()
      .mapToDouble(Counter::count)
      .sum();
    
    Double totalCount = meterRegistry.find("http.request").counters()
      .stream()
      .mapToDouble(Counter::count)
      .sum();
    
    return (successCount / totalCount) * 100;
  }
}
```

Monitoring:
```yaml
spring:
  prometheus:
    metrics:
      export:
        enabled: true
```

Alert when approaching error budget:
```
ALERT ErrorBudgetExhausted
  IF (1 - availability) > error_budget_remaining
  FOR 5m
```

Benefit: objective reliability targets, error budgeting guides risk decisions.

Pitfall: SLOs too ambitious (burnout), SLOs too lenient (customer dissatisfaction).

---

### Q412: What is feature flag lifecycle management?

Feature flags have lifecycle: planning → rollout → monitoring → cleanup.

Lifecycle stages:
```
Design:
  - Define toggle name, description
  - Identify rollout strategy (%, users, regions)
  - Owner, expiration date

Rollout:
  - Start at 0% (verify no code issues)
  - Gradually increase (1%, 5%, 10%, 50%, 100%)
  - Monitor metrics, error rates
  - Rollback capability

Monitoring:
  - Track flag usage
  - Identify clients still using old feature
  - Monitor performance impact

Cleanup:
  - Remove flag from code (6 months after 100% rollout)
  - Delete from toggle service
  - Archive configuration
```

Example (FF4j):
```yaml
ff4j:
  features:
    new_checkout:
      enabled: true
      description: "New checkout flow with wallet support"
      permissions: []
      properties:
        rollout-percent: 10 # 10% of users
        owner: "payments-team"
        created-date: "2024-01-01"
        target-removal: "2024-06-01"
```

Canary rollout (user-based):
```java
@Component
public class FeatureFlagService {
  @Autowired FF4j ff4j;
  
  public boolean isNewCheckoutEnabled(String userId) {
    if (!ff4j.check("new_checkout")) return false;
    
    // Rolling out to 10% of users (hash-based)
    int hashValue = userId.hashCode() % 100;
    int rolloutPercent = Integer.parseInt(
      ff4j.getFeature("new_checkout").getProperty("rollout-percent").asString());
    
    return hashValue < rolloutPercent;
  }
}

@RestController
public class CheckoutController {
  @Autowired FeatureFlagService featureFlagService;
  
  @PostMapping("/checkout")
  public ResponseEntity<?> checkout(@RequestBody CheckoutRequest request, @RequestHeader("User-Id") String userId) {
    if (featureFlagService.isNewCheckoutEnabled(userId)) {
      return ResponseEntity.ok(newCheckoutService.process(request));
    } else {
      return ResponseEntity.ok(legacyCheckoutService.process(request));
    }
  }
}
```

Automated cleanup:
```java
@Component
public class FlagCleanupScheduler {
  @Scheduled(cron = "0 0 0 * * MON") // weekly
  public void cleanupExpiredFlags() {
    ff4j.getFeatures().stream()
      .filter(f -> LocalDate.now().isAfter(f.getTargetRemovalDate()))
      .forEach(f -> {
        log.info("Removing expired flag: {}", f.getName());
        ff4j.deleteFeature(f.getName());
      });
  }
}
```

Benefit: safe feature rollout, quick rollback, A/B testing.

Pitfall: flag accumulation (flag debt); enforce cleanup deadline.

---

### Q413: What is Spring Web Services (SOAP)?

Spring Web Services (Spring-WS) provides SOAP/XML web services support (legacy).

WSDL (Web Services Description Language):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/">
  <types>
    <xsd:schema>
      <xsd:element name="GetOrderRequest">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element name="orderId" type="xsd:long"/>
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
    </xsd:schema>
  </types>
  
  <message name="GetOrderRequest">
    <part name="parameters" element="GetOrderRequest"/>
  </message>
</definitions>
```

Spring-WS endpoint:
```java
@Endpoint
public class OrderEndpoint {
  @Autowired OrderService orderService;
  
  @PayloadRoot(namespace = "http://example.com/orders", localPart = "GetOrderRequest")
  @ResponsePayload
  public GetOrderResponse getOrder(@RequestPayload GetOrderRequest request) {
    Order order = orderService.getOrder(request.getOrderId());
    GetOrderResponse response = new GetOrderResponse();
    response.setOrder(mapToDto(order));
    return response;
  }
}
```

Configuration:
```java
@Configuration
@EnableWs
public class WebServiceConfig implements ServletRegistrationBean {
  @Bean
  public ServletRegistrationBean<MessageDispatcherServlet> messageDispatcherServlet() {
    MessageDispatcherServlet servlet = new MessageDispatcherServlet();
    servlet.setApplicationContext(applicationContext);
    return new ServletRegistrationBean<>(servlet, "/ws/*");
  }
}
```

SOAP vs REST:
- SOAP: formal contract (WSDL), XML verbose, mature tooling, legacy
- REST: simpler, JSON lightweight, more modern, preferred

Benefit: strongly typed, formal contracts (enterprise systems).

Pitfall: SOAP complexity, XML verbosity; REST preferable for new services.

---

### Q414: What is database sharding strategy?

Sharding: partition data across multiple databases (horizontal scaling).

Shard key strategies:

Range-based:
```sql
-- Shard 1: user_id 1-1000000
-- Shard 2: user_id 1000001-2000000
-- Shard 3: user_id 2000001-3000000

SELECT * FROM orders WHERE user_id = 12345;
-- Route to Shard 1 (12345 in range 1-1000000)
```

Hash-based:
```java
public int getShardId(Long userId) {
  return (int) (userId % numberOfShards); // 0-9 for 10 shards
}

// user_id=1234 → shard 4 (1234 % 10)
// user_id=5678 → shard 8 (5678 % 10)
```

Directory-based (lookup table):
```
Shard lookup table:
user_id | shard_id
1       | 2
2       | 5
3       | 1
```

Sharding implementation (custom datasource router):
```java
@Component
public class ShardingDataSourceRouter extends AbstractRoutingDataSource {
  @Override
  protected Object determineCurrentLookupKey() {
    Long userId = ShardingContext.getCurrentUserId();
    int shardId = userId.intValue() % 10;
    return "shard_" + shardId;
  }
}

@Configuration
public class DataSourceConfig {
  @Bean
  public DataSource shardedDataSource() {
    AbstractRoutingDataSource ds = new ShardingDataSourceRouter();
    Map<Object, Object> shards = new HashMap<>();
    for (int i = 0; i < 10; i++) {
      shards.put("shard_" + i, createDataSource("shard-" + i));
    }
    ds.setTargetDataSources(shards);
    return ds;
  }
}
```

Resharding (add new shards): expensive operation
```
Old: 10 shards
New: 20 shards
Result: 50% of data must be migrated to new shards
```

Trade-off: horizontal scaling, but cross-shard queries complex, resharding cost.

Pitfall: shard hotspot (some shards busier), uneven distribution (poor shard key selection).

---

### Q415: What are transaction isolation levels (serializable, repeatable-read, read-committed)?

ACID serializability: transactions execute in isolation (as if sequential).

Isolation levels (lowest → highest):

READ UNCOMMITTED: dirty reads allowed
```
T1: writes X=5
T2: reads X=5 (uncommitted, may rollback)
```

READ COMMITTED: dirty reads prevented
```
T1: writes X=5
T2: cannot read X until T1 commits
```

REPEATABLE READ: non-repeatable reads prevented
```
T1: reads X=5
T2: updates X=10
T1: reads X again → still 5 (repeatable, matches first read)
```

SERIALIZABLE: phantoms prevented (highest isolation, lowest concurrency)
```
T1: selects all orders WHERE status='PENDING'
T2: inserts new order with status='PENDING'
T1: select again → might see new row (phantom read)
```

Spring configuration:
```java
@Service
public class OrderService {
  @Transactional(isolation = Isolation.SERIALIZABLE)
  public OrderSummary getOrderSummary(String status) {
    List<Order> orders = orderRepository.findByStatus(status);
    return new OrderSummary(orders.size(), orders.stream().mapToDouble(Order::getAmount).sum());
  }
}
```

Default isolation level (PostgreSQL): Read Committed

Trade-off: higher isolation = fewer anomalies but lower concurrency (locks, deadlocks).

Pitfall: SERIALIZABLE can cause deadlocks; use optimistic locking (version column) instead.

---

### Q416: What is optimistic locking?

Optimistic locking: assumes conflicts rare; detect conflicts at commit time using version column.

Example:
```java
@Entity
public class Order {
  @Id private Long id;
  @Version private Long version; // optimistic lock version
  private String status;
  private double amount;
}

// Concurrent update scenario
// T1: reads Order(id=1, version=1, status='PENDING')
// T2: reads Order(id=1, version=1, status='PENDING')
// T1: updates to COMPLETED (version → 2)
// T2: tries to update → StaleObjectStateException (version mismatch)

@Service
public class OrderService {
  @Transactional
  public Order updateStatus(Long id, String newStatus) {
    Order order = orderRepository.findById(id).get();
    order.setStatus(newStatus);
    return orderRepository.save(order); // may throw StaleObjectStateException
  }
}
```

Handle conflict:
```java
@RestController
public class OrderController {
  @ExceptionHandler(StaleObjectStateException.class)
  public ResponseEntity<?> handleOptimisticLockFailure(StaleObjectStateException e) {
    return ResponseEntity.status(409).body(Map.of("error", "Order updated by another user; please retry"));
  }
  
  @PutMapping("/orders/{id}")
  public ResponseEntity<Order> updateOrder(@PathVariable Long id, @RequestBody Order updates) {
    try {
      return ResponseEntity.ok(orderService.updateStatus(id, updates.getStatus()));
    } catch (StaleObjectStateException e) {
      return handleOptimisticLockFailure(e);
    }
  }
}
```

Benefit: no locks (high concurrency), conflict detection.

Pitfall: conflicts trigger manual retry; frequent conflicts indicate design issue.

---

### Q417: What is JSON Web Token (JWT) and how to validate?

JWT: stateless token with encoded claims (no server-side session).

Structure: Header.Payload.Signature
```
Header: {"alg": "HS256", "typ": "JWT"}
Payload: {"sub": "user123", "email": "user@example.com", "exp": 1234567890}
Signature: HMACSHA256(Header.Payload, secret_key)
```

Spring Security JWT validation:
```java
@Configuration
@EnableWebSecurity
public class JwtConfig {
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
      .authorizeHttpRequests(auth -> auth
        .requestMatchers("/login").permitAll()
        .anyRequest().authenticated())
      .oauth2ResourceServer(oauth2 -> oauth2.jwt());
    return http.build();
  }
  
  @Bean
  public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withSecretKey(getSecretKey()).build();
  }
  
  private SecretKey getSecretKey() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
  }
}
```

Generate JWT:
```java
@RestController
@RequestMapping("/auth")
public class AuthController {
  @Autowired JwtProvider jwtProvider;
  
  @PostMapping("/login")
  public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    if (userService.validateCredentials(request.getUsername(), request.getPassword())) {
      String token = jwtProvider.generateToken(request.getUsername());
      return ResponseEntity.ok(Map.of("token", token));
    }
    return ResponseEntity.status(401).body("Invalid credentials");
  }
}

@Component
public class JwtProvider {
  @Value("${jwt.secret}") private String jwtSecret;
  @Value("${jwt.expiration}") private long expirationMs;
  
  public String generateToken(String username) {
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + expirationMs);
    
    return Jwts.builder()
      .setSubject(username)
      .setIssuedAt(now)
      .setExpiration(expiryDate)
      .signWith(SignatureAlgorithm.HS512, jwtSecret)
      .compact();
  }
  
  public String getUsernameFromToken(String token) {
    return Jwts.parser()
      .setSigningKey(jwtSecret)
      .parseClaimsJws(token)
      .getBody()
      .getSubject();
  }
}
```

Trade-off: stateless (scalable), but token revocation difficult (use blacklist).

Pitfall: secret key compromise (rotate, use strong entropy).

---

### Q418: What is server-sent events (SSE) vs WebSocket?

SSE: server pushes real-time data to client (unidirectional, HTTP-based).

Example (SSE):
```java
@RestController
@RequestMapping("/sse")
public class OrderSseController {
  @GetMapping("/orders/{id}")
  public SseEmitter getOrderUpdates(@PathVariable Long id) {
    SseEmitter emitter = new SseEmitter();
    
    executorService.execute(() -> {
      try {
        Order order = orderRepository.findById(id).get();
        
        while (order.getStatus().equals("PENDING")) {
          emitter.send(SseEmitter.event()
            .name("order-update")
            .data(order)
            .dispatchTimeout(1000));
          
          Thread.sleep(10000); // poll every 10 seconds
          order = orderRepository.findById(id).get();
        }
        
        emitter.complete();
      } catch (IOException e) {
        emitter.completeWithError(e);
      }
    });
    
    return emitter;
  }
}
```

WebSocket: bidirectional, persistent connection.

Example (WebSocket):
```java
@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {
  @Override
  public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
    registry.addHandler(orderWebSocketHandler(), "/ws/orders");
  }
  
  @Bean
  public WebSocketHandler orderWebSocketHandler() {
    return new OrderWebSocketHandler();
  }
}

@Component
public class OrderWebSocketHandler extends TextWebSocketHandler {
  private Set<WebSocketSession> sessions = new CopyOnWriteArraySet<>();
  
  @Override
  public void afterConnectionEstablished(WebSocketSession session) {
    sessions.add(session);
  }
  
  @Override
  public void handleTextMessage(WebSocketSession session, TextMessage message) {
    // Client sends order update request
    Long orderId = Long.parseLong(message.getPayload());
    Order order = orderRepository.findById(orderId).get();
    
    // Broadcast to all connected clients
    sessions.forEach(s -> {
      try {
        s.sendMessage(new TextMessage(objectMapper.writeValueAsString(order)));
      } catch (IOException e) {
        // handle error
      }
    });
  }
}
```

SSE vs WebSocket:
- SSE: simpler (HTTP), built-in browser support, unidirectional
- WebSocket: bidirectional, lower overhead, real-time games/chat

Benefit: real-time updates without polling.

Pitfall: resource-intensive (open connections); limit concurrent connections.

---

### Q419: What is circuit breaker with fallback strategies?

Circuit breaker prevents cascading failures (fail-fast when downstream unavailable).

States: Closed (happy path) → Open (too many failures) → Half-Open (test recovery).

Fallback strategies:

1. Return cached data:
```java
@Service
public class OrderService {
  @Autowired CacheService cache;
  @Autowired PaymentClient paymentClient;
  
  @CircuitBreaker(name = "paymentService", fallbackMethod = "chargeWithCache")
  public Payment charge(Order order) {
    return paymentClient.charge(order);
  }
  
  public Payment chargeWithCache(Order order, Exception e) {
    Payment cached = cache.get("payment:" + order.getId());
    if (cached != null) {
      return cached; // return stale cached data
    }
    throw new ServiceUnavailableException("Payment service unavailable");
  }
}
```

2. Queue for later processing:
```java
public Payment chargeQueueForRetry(Order order, Exception e) {
  retryQueue.add(new PaymentRetry(order.getId(), order));
  return new Payment(status = "PENDING_RETRY"); // return PENDING status
}
```

3. Degrade gracefully:
```java
public Payment chargeWithDegradation(Order order, Exception e) {
  // Skip validation, charge immediately
  Order simplified = new Order(order.getId(), order.getAmount()); // strip fields
  return new Payment(status = "CHARGED_DEGRADED");
}
```

Benefit: resilience, prevents cascading failures.

Pitfall: fallback complexity (choose appropriate strategy per use case).

---

### Q420: What is rate limiting with token bucket algorithm?

Token bucket: tokens refill at fixed rate; each request costs tokens.

Example:
```
Bucket capacity: 100 tokens
Refill rate: 10 tokens/second

Time 0s: 100 tokens
Request 1 (costs 1): 99 tokens
Request 2 (costs 1): 98 tokens
...after 10 requests: 90 tokens
...after 1 second: 100 tokens (refilled to capacity)
After 10 seconds: 100 tokens (refilled, capped at capacity)
```

Implementation (Redis-backed):
```java
@Component
public class TokenBucketLimiter {
  @Autowired StringRedisTemplate redisTemplate;
  
  private final int capacity = 100;
  private final int refillRate = 10; // tokens/second
  
  public boolean allowRequest(String key) {
    String bucketKey = "bucket:" + key;
    String refillKey = "refill:" + key;
    
    // Get current tokens and last refill time
    Long tokens = redisTemplate.opsForValue().increment(bucketKey, 0);
    Long lastRefill = Long.parseLong(redisTemplate.opsForValue().get(refillKey) != null ? 
      redisTemplate.opsForValue().get(refillKey) : "0");
    
    // Calculate tokens to add based on time elapsed
    long now = System.currentTimeMillis() / 1000;
    long secondsElapsed = now - lastRefill;
    long tokensToAdd = secondsElapsed * refillRate;
    
    long newTokens = Math.min(capacity, tokens + tokensToAdd);
    
    if (newTokens > 0) {
      redisTemplate.opsForValue().set(bucketKey, String.valueOf(newTokens - 1));
      redisTemplate.opsForValue().set(refillKey, String.valueOf(now));
      return true;
    }
    return false;
  }
}
```

Use in controller:
```java
@RestController
public class OrderController {
  @Autowired TokenBucketLimiter limiter;
  
  @GetMapping("/orders")
  public ResponseEntity<?> listOrders(@RequestHeader("X-User-Id") String userId) {
    if (!limiter.allowRequest(userId)) {
      return ResponseEntity.status(429).body("Rate limit exceeded");
    }
    return ResponseEntity.ok(orderService.list());
  }
}
```

Benefit: smooth rate limiting (bursty traffic allowed up to capacity).

Pitfall: distributed implementation complex (clock skew, race conditions).

---

### Q421: What is database replication (master-slave, multi-master)?

Replication: copy data across multiple servers for redundancy & read scaling.

Master-slave (primary-replica):
```
Master:
- Handles reads & writes
- Writes to binary log
- Slaves read binary log

Slave:
- Reads-only (typically)
- Applies master's changes
- Lag possible (asynchronous)

Topology:
Master → Slave1 → Slave2 (cascade)
Master
├── Slave1
├── Slave2
└── Slave3
```

Multi-master (circular):
```
Master1 ↔ Master2
Both handle reads & writes
Conflict resolution: last-write-wins, custom merge
```

Spring configuration (read-write splitting):
```java
@Configuration
public class DataSourceConfig {
  @Bean
  public DataSource masterDataSource() {
    return createDataSource("master-host");
  }
  
  @Bean
  public DataSource slaveDataSource() {
    return createDataSource("slave-host");
  }
  
  @Bean
  public DataSource routingDataSource() {
    AbstractRoutingDataSource ds = new AbstractRoutingDataSource() {
      @Override
      protected Object determineCurrentLookupKey() {
        return TransactionSynchronizationManager.isCurrentTransactionReadOnly() ? "slave" : "master";
      }
    };
    Map<Object, Object> sources = new HashMap<>();
    sources.put("master", masterDataSource());
    sources.put("slave", slaveDataSource());
    ds.setTargetDataSources(sources);
    return ds;
  }
}

@Service
public class OrderService {
  @Transactional(readOnly = true) // routes to slave
  public Order getOrder(Long id) {
    return orderRepository.findById(id);
  }
  
  @Transactional // routes to master
  public Order createOrder(Order order) {
    return orderRepository.save(order);
  }
}
```

Benefit: read scalability, high availability (failover).

Pitfall: replication lag (reads may be stale), complexity (failover is manual or requires tool).

---

### Q422: What is dependency version management (Maven BOM)?

BOM (Bill of Materials): centralized version control for Maven dependencies.

Example (Spring Boot BOM):
```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-dependencies</artifactId>
      <version>3.2.0</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>

<dependencies>
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
    <!-- version omitted; inherited from BOM -->
  </dependency>
</dependencies>
```

Custom BOM:
```xml
<!-- pom.xml (library) -->
<artifactId>myapp-bom</artifactId>
<packaging>pom</packaging>

<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.mycompany</groupId>
      <artifactId>order-service-api</artifactId>
      <version>1.0.0</version>
    </dependency>
    <dependency>
      <groupId>com.mycompany</groupId>
      <artifactId>payment-service-api</artifactId>
      <version>1.1.0</version>
    </dependency>
  </dependencies>
</dependencyManagement>

<!-- pom.xml (consumer) -->
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.mycompany</groupId>
      <artifactId>myapp-bom</artifactId>
      <version>1.0.0</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>

<dependencies>
  <dependency>
    <groupId>com.mycompany</groupId>
    <artifactId>order-service-api</artifactId>
    <!-- version inherited from BOM -->
  </dependency>
</dependencies>
```

Benefit: consistent versions across modules, easy upgrades.

Pitfall: overly strict versioning (blocks necessary updates).

---

### Q423: What is property source hierarchy in Spring?

Spring loads properties from multiple sources (command-line > env vars > application.properties).

Hierarchy (highest → lowest priority):
1. Command-line arguments: `--server.port=9000`
2. Environment variables: `export SERVER_PORT=9000`
3. OS environment: `$SERVER_PORT`
4. application-[profile].properties (active profile)
5. application.properties
6. @PropertySource annotations
7. System properties (System.getProperty())

Example:
```properties
# application.properties (default)
server.port=8080
logging.level=INFO

# application-prod.properties (production profile)
server.port=8443
logging.level=WARN
database.url=jdbc:mysql://prod-db:3306/orders
```

Activate profile:
```bash
java -jar app.jar --spring.profiles.active=prod
export SPRING_PROFILES_ACTIVE=prod
```

Custom property source:
```java
@Configuration
@PropertySource("classpath:custom.properties")
public class AppConfig {
  @Value("${custom.value}")
  private String customValue;
}
```

Environment access:
```java
@Component
public class ConfigLoader {
  @Autowired Environment env;
  
  public void loadConfig() {
    String port = env.getProperty("server.port");
    String[] profiles = env.getActiveProfiles();
  }
}
```

Benefit: environment-specific config without code changes.

Pitfall: property name conflicts (same property in multiple sources); explicit priority necessary.

---

### Q424: What is health checks and liveness probes in Kubernetes?

Kubernetes uses probes to manage pod lifecycle:

Liveness: is container alive? If not, restart.
Readiness: is container ready for traffic? If not, remove from load balancer.
Startup: has startup logic completed? If not, defer liveness/readiness checks.

Spring Boot Actuator health endpoint:
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health
  endpoint:
    health:
      show-details: always
```

Endpoint: GET /actuator/health
```json
{
  "status": "UP",
  "components": {
    "db": {"status": "UP"},
    "diskSpace": {"status": "UP"},
    "redis": {"status": "UP"}
  }
}
```

Custom health check:
```java
@Component
public class DatabaseHealthIndicator extends AbstractHealthIndicator {
  @Autowired DataSource dataSource;
  
  @Override
  protected void doHealthCheck(Health.Builder builder) {
    try (Connection conn = dataSource.getConnection()) {
      conn.prepareStatement("SELECT 1").executeQuery();
      builder.up().withDetail("database", "connected");
    } catch (SQLException e) {
      builder.down().withDetail("error", e.getMessage());
    }
  }
}
```

Kubernetes configuration:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: order-service
spec:
  containers:
  - name: app
    image: order-service:latest
    livenessProbe:
      httpGet:
        path: /actuator/health/liveness
        port: 8080
      initialDelaySeconds: 30
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /actuator/health/readiness
        port: 8080
      initialDelaySeconds: 10
      periodSeconds: 5
    startupProbe:
      httpGet:
        path: /actuator/health/startup
        port: 8080
      failureThreshold: 30
      periodSeconds: 1
```

Benefit: automated pod recovery, traffic management.

Pitfall: incorrect health checks (false positives, cascading failures).

---

### Q425: What is graceful shutdown in Spring applications?

Graceful shutdown: complete in-flight requests, close resources, exit cleanly.

Configuration:
```yaml
server:
  shutdown: graceful
spring:
  lifecycle:
    timeout-per-shutdown-phase: 30s # max 30 seconds to shutdown
```

Custom shutdown hook:
```java
@Component
public class GracefulShutdownManager {
  @Autowired ApplicationContext applicationContext;
  @Autowired ExecutorService executorService;
  
  @PreDestroy
  public void shutdown() {
    log.info("Starting graceful shutdown");
    
    // Stop accepting new requests
    ServletWebServerApplicationContext context = (ServletWebServerApplicationContext) applicationContext;
    context.getWebServer().stop();
    
    // Wait for in-flight requests (max 30s)
    executorService.shutdown();
    try {
      boolean terminated = executorService.awaitTermination(30, TimeUnit.SECONDS);
      if (!terminated) {
        log.warn("Executor did not terminate within timeout; forcing shutdown");
        executorService.shutdownNow();
      }
    } catch (InterruptedException e) {
      executorService.shutdownNow();
      Thread.currentThread().interrupt();
    }
    
    // Close database, cache, message broker connections
    closeConnections();
    
    log.info("Graceful shutdown complete");
  }
  
  private void closeConnections() {
    // close all managed resources
  }
}
```

Kubernetes integration:
```yaml
apiVersion: v1
kind: Pod
spec:
  terminationGracePeriodSeconds: 30 # allow 30s for graceful shutdown
  containers:
  - name: app
    lifecycle:
      preStop:
        exec:
          command: ["/bin/sh", "-c", "sleep 5"] # delay termination, allow load balancer to remove pod
```

Benefit: zero data loss, request completion, resource cleanup.

Pitfall: timeout too long delays deployment; too short causes request termination.

---

### Q426: What are advanced Kubernetes patterns (DaemonSet, StatefulSet, Job)?

DaemonSet: ensure pod runs on every node (monitoring, logging agents).
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: monitoring-agent
spec:
  selector:
    matchLabels:
      app: monitoring
  template:
    metadata:
      labels:
        app: monitoring
    spec:
      containers:
      - name: agent
        image: monitoring-agent:latest
```

StatefulSet: ordered, stable identity (databases, stateful services).
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mysql
spec:
  serviceName: mysql # headless service
  replicas: 3
  selector:
    matchLabels:
      app: mysql
  template:
    metadata:
      labels:
        app: mysql
    spec:
      containers:
      - name: mysql
        image: mysql:8.0
        volumeMounts:
        - name: data
          mountPath: /var/lib/mysql
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 100Gi
```

Job: one-time tasks (batch processing).
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: bulk-import
spec:
  completions: 10 # run 10 pods to completion
  parallelism: 5 # 5 pods in parallel
  backoffLimit: 3 # retry max 3 times
  template:
    spec:
      containers:
      - name: importer
        image: order-importer:latest
      restartPolicy: Never
```

CronJob: periodic jobs (scheduled tasks).
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: daily-cleanup
spec:
  schedule: "0 2 * * *" # 2 AM daily
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: cleanup
            image: cleanup-job:latest
          restartPolicy: Never
```

Benefit: specialized workload support, self-healing.

Pitfall: DaemonSet resource contention; StatefulSet complexity; Job/CronJob error handling.

---

### Q427: What is Helm and its use in Kubernetes deployment?

Helm: package manager for Kubernetes (templates, versioning, release management).

Helm chart structure:
```
my-app-chart/
├── Chart.yaml
├── values.yaml
├── values-prod.yaml
├── templates/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── configmap.yaml
│   └── secrets.yaml
```

Chart.yaml:
```yaml
apiVersion: v2
name: my-app
version: 1.0.0
appVersion: 1.0.0
```

values.yaml:
```yaml
replicaCount: 3
image:
  repository: order-service
  tag: 1.0.0
  pullPolicy: IfNotPresent
service:
  type: ClusterIP
  port: 8080
ingress:
  enabled: true
  hosts:
  - host: orders.example.com
    paths:
    - path: /
      pathType: Prefix
```

deployment.yaml (template):
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-{{ .Chart.Name }}
spec:
  replicas: {{ .Values.replicaCount }}
  template:
    spec:
      containers:
      - name: app
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
```

Deploy:
```bash
# Install
helm install my-release ./my-app-chart

# Upgrade with prod values
helm upgrade my-release ./my-app-chart -f values-prod.yaml

# List releases
helm list

# Rollback
helm rollback my-release 1
```

Benefit: templating, versioning, release management, rollback capability.

Pitfall: complex templates hard to debug; test thoroughly.

---

### Q428: What is container security (image scanning, secrets)?

Image scanning: check for vulnerabilities (CVEs) before deployment.

Tools: Trivy, Snyk, Anchore.

Example (Trivy scan):
```bash
trivy image order-service:1.0.0
# Output:
# Library | Vulnerability | Severity | Fixed Version
# log4j  | CVE-2021-44228 | CRITICAL | 2.17.0
```

Secrets in containers: never hardcode; use volume mounts.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
type: Opaque
stringData:
  username: root
  password: secret123

---
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: order-service:latest
    env:
    - name: DB_USER
      valueFrom:
        secretKeyRef:
          name: db-credentials
          key: username
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-credentials
          key: password
```

Non-root containers:
```dockerfile
FROM openjdk:11
RUN useradd -m appuser
USER appuser
ENTRYPOINT ["java", "-jar", "app.jar"]
```

```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: app
    image: order-service:latest
    securityContext:
      readOnlyRootFilesystem: true
```

Benefit: reduced attack surface, compliance.

Pitfall: image scanning false positives; container security is ongoing (not one-time).

---

### Q429: What is distributed tracing (Jaeger, Zipkin)?

Distributed tracing: track requests across microservices (trace ID → spans).

Span: unit of work (RPC call, database query).

Example (Spring Cloud Sleuth + Jaeger):
```xml
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-starter-sleuth</artifactId>
</dependency>
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-sleuth-zipkin</artifactId>
</dependency>
```

Properties:
```yaml
spring:
  sleuth:
    sampler:
      rate: 0.1 # sample 10% of requests
  zipkin:
    base-url: http://zipkin:9411
```

Enable tracing in code:
```java
@RestController
public class OrderController {
  @Autowired OrderService orderService;
  
  @GetMapping("/orders/{id}")
  public ResponseEntity<Order> getOrder(@PathVariable Long id) {
    Order order = orderService.getOrder(id); // creates span
    return ResponseEntity.ok(order);
  }
}

@Service
public class OrderService {
  @Autowired PaymentClient paymentClient;
  
  public Order getOrder(Long id) {
    Order order = orderRepository.findById(id); // child span
    Payment payment = paymentClient.getPayment(order.getId()); // child span
    return order;
  }
}
```

Jaeger UI: http://localhost:16686
- Visualize traces (request flow across services)
- Identify bottlenecks (slow spans)
- Error tracing (find where failure occurred)

Benefit: end-to-end request visibility, performance analysis.

Pitfall: tracing overhead (sampling helps); sensitive data in spans.

---

### Q430: What is API gateway rate limiting patterns?

API Gateway implements rate limiting for entire application.

Example (Spring Cloud Gateway):
```yaml
spring:
  cloud:
    gateway:
      routes:
      - id: order-service
        uri: http://order-service:8080
        predicates:
        - Path=/api/orders/**
        filters:
        - name: RequestRateLimiter
          args:
            redis-rate-limiter:
              replenishRate: 10
              burstCapacity: 20
              key-resolver: "#{T(org.springframework.cloud.gateway.support.ipaddress.IpAddressKeyResolver).getInstance()}"
```

Custom key resolver (by user ID):
```java
@Configuration
public class RateLimitConfig {
  @Bean
  public KeyResolver userIdKeyResolver() {
    return exchange -> Mono.just(extract(exchange.getRequest(), "X-User-Id"));
  }
  
  private String extract(ServerHttpRequest request, String headerName) {
    return request.getHeaders().getFirst(headerName) != null ? 
      request.getHeaders().getFirst(headerName) : "ANONYMOUS";
  }
}
```

Tiered rate limiting:
```yaml
filters:
- name: RequestRateLimiter
  args:
    redis-rate-limiter:
      free-tier:
        replenishRate: 10
        burstCapacity: 20
      premium-tier:
        replenishRate: 100
        burstCapacity: 200
```

Benefit: protects backend services, fairness enforcement, DDoS mitigation.

Pitfall: rate limit too strict rejects legitimate traffic; too lenient fails to protect.

---

### Q431: What is container orchestration operator pattern?

Operator: custom controller managing Kubernetes-native resources (CRD).

Example (database operator):
```yaml
apiVersion: databases.example.com/v1
kind: MySQLCluster
metadata:
  name: production-db
spec:
  version: 8.0
  replicas: 3
  storage: 100Gi
  backup:
    enabled: true
    schedule: "0 2 * * *"
```

Operator watches for MySQLCluster resources and auto-manages:
- Master-slave setup
- Replication
- Backups
- Failover

Implementation (custom controller):
```java
@RestController
@RequestMapping("/api/v1/clustersscaler")
public class MySQLOperatorController {
  @Autowired KubernetesClient kubeClient;
  
  @Scheduled(fixedRate = 10000) // watch every 10s
  public void reconcileClusters() {
    kubeClient.customResources(MySQLCluster.class).list().forEach(cluster -> {
      String clusterName = cluster.getMetadata().getName();
      int desiredReplicas = cluster.getSpec().getReplicas();
      
      // Patch StatefulSet to match desired replicas
      kubeClient.apps().statefulSets().inNamespace(cluster.getMetadata().getNamespace())
        .withName(clusterName).edit(ss -> {
          ss.getSpec().setReplicas(desiredReplicas);
          return ss;
        });
    });
  }
}
```

Benefits: Kubernetes-native, auto-healing, operator code reusable.

Pitfall: operator complexity; use existing operators (Prometheus, Kafka) when possible.

---

### Q432: What is cost optimization for cloud infrastructure?

Cost optimization strategies:

Reserved instances: pre-pay for capacity, 40-70% discount vs on-demand
```
3-year reserved: 70% discount
1-year reserved: 40% discount
On-demand: full price
```

Spot instances: unused capacity at discount (up to 90% off), suitable for batch jobs
```
Hourly price varies based on supply
Risk: instance can be terminated if demand increases
Use: batch processing, non-critical workloads
```

Right-sizing: use smallest instance meeting requirements
```
Monitor CPU/memory utilization
Downscale if average < 30%
```

Auto-scaling: scale down during off-peak
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: order-service-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: order-service
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 15
```

Storage optimization: use cheaper tiers for cold data
```
Hot storage: SSD (fast, expensive)
Warm storage: HDD (slow, cheaper)
Cold storage: Archive (very slow, very cheap)
```

Data transfer optimization: avoid inter-region transfers (expensive)

Benefit: reduced cloud costs, proportional to utilization.

Pitfall: over-aggressive cost optimization causes performance issues; balance cost & performance.

---

### Q433: What is API documentation best practices (OpenAPI/Swagger)?

OpenAPI/Swagger provides machine-readable API specification.

Example (Spring Boot with Springdoc):
```xml
<dependency>
  <groupId>org.springdoc</groupId>
  <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
  <version>2.0.0</version>
</dependency>
```

Configuration:
```yaml
springdoc:
  api-docs:
    path: /api-docs
  swagger-ui:
    path: /swagger-ui.html
    enabled: true
```

Annotated controller:
```java
@RestController
@RequestMapping("/api/v1/orders")
@Tag(name = "Orders", description = "Order management API")
public class OrderController {
  @GetMapping("/{id}")
  @Operation(summary = "Get order by ID", description = "Retrieves an order and its details")
  @ApiResponse(responseCode = "200", description = "Order found", content = {
    @Content(mediaType = "application/json", schema = @Schema(implementation = Order.class))
  })
  @ApiResponse(responseCode = "404", description = "Order not found")
  public ResponseEntity<Order> getOrder(
    @Parameter(description = "Order ID", required = true)
    @PathVariable Long id) {
    return ResponseEntity.ok(orderService.getOrder(id));
  }
  
  @PostMapping
  @Operation(summary = "Create order")
  public ResponseEntity<Order> createOrder(@RequestBody @Valid CreateOrderRequest request) {
    return ResponseEntity.status(201).body(orderService.create(request));
  }
}

@Schema(description = "Order creation request")
record CreateOrderRequest(
  @Schema(description = "User ID", example = "123")
  Long userId,
  
  @Schema(description = "Order amount", example = "99.99")
  @Positive(message = "Amount must be positive")
  double amount
) {}
```

Generated OpenAPI spec: http://localhost:8080/api-docs

Benefits: auto-generated docs, interactive Swagger UI, client SDK generation.

Pitfall: docs get stale (keep annotations in sync with code); use linting tools.

---

### Q434: What is contract testing (Pact, Spring Cloud Contract)?

Contract testing: verify service interactions match agreed contracts.

Pact (consumer-driven):
```java
// Consumer test (Order Service expects Payment Service behavior)
@ExtendWith(PactConsumerTestExt.class)
@PactTestFor(providerName = "PaymentService", port = "9000")
public class PaymentServiceConsumerTest {
  
  @Pact(consumer = "OrderService", provider = "PaymentService")
  public RequestResponsePact createPaymentContract(PactBuilder pactBuilder) {
    return pactBuilder
      .uponReceiving("a request to charge payment")
      .path("/payments/charge")
      .method("POST")
      .body(Map.of("orderId", 123, "amount", 99.99))
      .willRespondWith()
      .status(200)
      .body(Map.of("transactionId", "txn-456", "status", "SUCCESS"))
      .toPact();
  }
  
  @Test
  @PactTestFor(pactMethod = "createPaymentContract")
  public void verifyChargePaymentContract() {
    Payment payment = paymentClient.charge(new Order(123L, 99.99));
    assertThat(payment.getTransactionId()).isEqualTo("txn-456");
    assertThat(payment.getStatus()).isEqualTo("SUCCESS");
  }
}
```

Spring Cloud Contract (provider-driven):
```groovy
// src/test/resources/contracts/payment/should-charge-payment.groovy
Contract.make {
  request {
    method 'POST'
    url '/payments/charge'
    body(
      orderId: 123,
      amount: 99.99
    )
  }
  response {
    status 200
    body(
      transactionId: 'txn-456',
      status: 'SUCCESS'
    )
  }
}
```

Verify contract in provider:
```java
@SpringBootTest
@AutoConfigureWireMock(port = 9000)
public class PaymentServiceContractTest extends PaymentServiceBase {
  @Autowired PaymentController paymentController;
  
  @Override
  public void invokePaymentServiceCharge() {
    // Provider implements contract
    Payment payment = paymentController.charge(new ChargeRequest(123, 99.99));
    this.payment = payment;
  }
}
```

Benefits: catches integration issues early, documents API contracts.

Pitfall: contract maintenance (breaking changes must be negotiated); both sides must use contract tests.

---

### Q435: What is test data management and factories?

Test data: consistent, realistic, version-controlled fixtures.

Factory pattern:
```java
public class OrderFactory {
  public static Order createDefaultOrder() {
    return new Order(1L, 100.0, "PENDING");
  }
  
  public static Order createWithStatus(String status) {
    return new Order(1L, 100.0, status);
  }
  
  public static Order createWithAmount(double amount) {
    return new Order(1L, amount, "PENDING");
  }
}

// Usage
Order order = OrderFactory.createWithStatus("COMPLETED");
```

Builder pattern (fluent):
```java
public class OrderBuilder {
  private Long id = 1L;
  private double amount = 100.0;
  private String status = "PENDING";
  
  public OrderBuilder withId(Long id) {
    this.id = id;
    return this;
  }
  
  public OrderBuilder withStatus(String status) {
    this.status = status;
    return this;
  }
  
  public Order build() {
    return new Order(id, amount, status);
  }
}

// Usage
Order order = new OrderBuilder()
  .withId(5L)
  .withStatus("SHIPPED")
  .build();
```

Test data seeding (database fixtures):
```java
@SpringBootTest
@Sql(scripts = {"classpath:orders-test-data.sql"})
public class OrderRepositoryTest {
  // tests use pre-populated data from SQL script
}
```

orders-test-data.sql:
```sql
INSERT INTO orders (id, user_id, amount, status) VALUES (1, 100, 50.0, 'PENDING');
INSERT INTO orders (id, user_id, amount, status) VALUES (2, 100, 75.0, 'COMPLETED');
```

Benefit: test isolation, reusable test data, readable tests.

Pitfall: test data drift (gets out of sync with schema); automate updates.

---

### Q436: What is continuous deployment (CD) and blue-green deployments?

Continuous Deployment: every commit to main automatically deploys to production (if tests pass).

Blue-green deployment: two identical production environments (blue, green); switch traffic.

```
Blue (old version, serving traffic):
- order-service:v1.0.0
- payment-service:v1.0.0

Green (new version, idle):
- order-service:v1.1.0
- payment-service:v1.1.0

Deploy process:
1. Deploy to Green
2. Test Green (smoke tests)
3. Switch load balancer to Green (instant cutover)
4. Keep Blue as rollback (revert traffic if issues)
5. After verification, tear down Blue
```

Implementation (Kubernetes):
```yaml
apiVersion: v1
kind: Service
metadata:
  name: order-service
spec:
  selector:
    app: order-service
    version: blue # selector points to blue
  ports:
  - port: 80
    targetPort: 8080

---
# Blue deployment (current)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: order-service-blue
spec:
  replicas: 3
  selector:
    matchLabels:
      app: order-service
      version: blue
  template:
    metadata:
      labels:
        app: order-service
        version: blue
    spec:
      containers:
      - name: order-service
        image: order-service:1.0.0

---
# Green deployment (new)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: order-service-green
spec:
  replicas: 3
  selector:
    matchLabels:
      app: order-service
      version: green
  template:
    metadata:
      labels:
        app: order-service
        version: green
    spec:
      containers:
      - name: order-service
        image: order-service:1.1.0
```

Switch to green:
```bash
kubectl patch service order-service -p '{"spec":{"selector":{"version":"green"}}}'
```

Rollback to blue:
```bash
kubectl patch service order-service -p '{"spec":{"selector":{"version":"blue"}}}'
```

Benefit: zero-downtime deployment, instant rollback.

Pitfall: requires double resources (blue + green); blue-green more expensive than canary.

---

### Q437: What is canary deployment?

Canary deployment: gradually roll out new version to % of traffic.

```
1% traffic → v1.1.0 (1 replica)
99% traffic → v1.0.0 (99 replicas)

Monitor metrics (error rate, latency)
If good: increase to 10%
If bad: rollback immediately
```

Implementation (Istio VirtualService):
```yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: order-service
spec:
  hosts:
  - order-service
  http:
  - match:
    - headers:
        user-type:
          exact: "canary"
    route:
    - destination:
        host: order-service
        port:
          number: 8080
        subset: v1.1.0
      weight: 100
  - route:
    - destination:
        host: order-service
        port:
          number: 8080
        subset: v1.0.0
      weight: 99
    - destination:
        host: order-service
        port:
          number: 8080
        subset: v1.1.0
      weight: 1
```

Automated canary (Flagger):
```yaml
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: order-service
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: order-service
  progressDeadlineSeconds: 300
  service:
    port: 8080
  analysis:
    interval: 1m
    threshold: 5 # max 5% error rate
    maxWeight: 50 # max 50% traffic
    stepWeight: 10 # increase by 10% per interval
    metrics:
    - name: error-rate
      thresholdRange:
        max: 5
      interval: 1m
    - name: latency
      thresholdRange:
        max: 500m
      interval: 1m
```

Benefit: gradual rollout, immediate rollback on issues, metrics-driven.

Pitfall: longer deployment time (phased rollout).

---

### Q438: What are mutation testing and code coverage?

Mutation testing: inject bugs (mutations) to verify tests catch them.

Example (PIT - Pitest):
```xml
<plugin>
  <groupId>org.pitest</groupId>
  <artifactId>pitest-maven</artifactId>
  <version>1.10.1</version>
</plugin>
```

Run:
```bash
mvn org.pitest:pitest-maven:mutationCoverage
```

Result: report shows mutations killed (test caught) vs survived (test missed).

```
Mutation: change > to >=
  Order amount = 100
  Original: if (amount > 50) → true
  Mutated: if (amount >= 50) → true
  Result: KILLED (test caught mutation)

Mutation: remove return statement
  Original: return orderRepository.findById(id)
  Mutated: return null
  Result: SURVIVED (test didn't catch null return)
  → Need to add test for null case
```

Code coverage: measure % of code executed by tests.

Example (JaCoCo):
```xml
<plugin>
  <groupId>org.jacoco</groupId>
  <artifactId>jacoco-maven-plugin</artifactId>
  <version>0.8.8</version>
  <executions>
    <execution>
      <goals>
        <goal>prepare-agent</goal>
      </goals>
    </execution>
  </executions>
</plugin>
```

Coverage metrics:
- Line coverage: % of lines executed
- Branch coverage: % of if/else branches taken
- Path coverage: % of execution paths covered

Benefit: mutation testing reveals weak tests; code coverage shows untested code.

Pitfall: high coverage doesn't guarantee good tests (need mutation testing); 100% coverage not always necessary.

---

### Q439: What is log aggregation (ELK, Splunk)?

Log aggregation: centralize logs from multiple services for analysis.

ELK Stack (Elasticsearch, Logstash, Kibana):

```
Application
  ↓ (logs via syslog/HTTP)
Logstash (parse, enrich)
  ↓
Elasticsearch (index, search)
  ↓
Kibana (visualize, alert)
```

Spring Boot with Logback + ELK:
```xml
<dependency>
  <groupId>net.logstash.logback</groupId>
  <artifactId>logstash-logback-encoder</artifactId>
  <version>7.2</version>
</dependency>
```

logback-spring.xml:
```xml
<appender name="LOGSTASH" class="net.logstash.logback.appender.LogstashTcpSocketAppender">
  <destination>logstash:5000</destination>
  <encoder class="net.logstash.logback.encoder.LogstashEncoder">
    <customFields>{"app": "order-service", "environment": "prod"}</customFields>
  </encoder>
</appender>

<root level="INFO">
  <appender-ref ref="LOGSTASH"/>
</root>
```

Kibana dashboard:
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"app": "order-service"}},
        {"match": {"level": "ERROR"}},
        {"range": {"timestamp": {"gte": "now-1h"}}}
      ]
    }
  }
}
```

Benefits: centralized logging, full-text search, alerting, trend analysis.

Pitfall: ELK complexity (storage, cost); managed services (DataDog, New Relic) simpler.

---

### Q440: What is incident response and postmortem process?

Incident response: structured process to handle production issues.

Phases:

Detection: monitoring alerts (error rate, latency spike)
```
Alert: error rate > 5% for 5 minutes
```

Triage: assess severity
```
SEV1 (critical): customers affected, revenue impact → page on-call
SEV2 (high): degraded service → notify team
SEV3 (low): minor issue → log for later
```

Response:
```
1. Establish war room (Slack, video call)
2. Incident commander delegates tasks
3. Parallel: investigate root cause, mitigate impact
4. Communication updates every 5 minutes
5. Implement workaround / rollback
```

Postmortem (blameless, learning-focused):
```
Timeline:
14:30 - error rate spike detected
14:35 - identified payment service timeouts
14:40 - triggered rollback to v1.0.0
14:50 - error rate normalized

Root cause:
Payment gateway introduced rate limiting (undisclosed)
→ Service exhausted connection pool

Action items:
1. Add circuit breaker for payment gateway (prevent resource exhaustion)
2. Implement health checks for external dependencies
3. Load test before deploying new versions
4. Improve alerting (detect latency before error rate spikes)
5. Document external service SLAs
```

Benefit: learning from incidents, system improvement, psychological safety.

Pitfall: blame-focused postmortems (suppress reporting); blameless culture essential.

---

### Q441: What is infrastructure as code (Terraform, CloudFormation)?

Infrastructure as Code: define cloud infrastructure in code (version-controlled, repeatable).

Terraform (cloud-agnostic):
```hcl
# main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "environment" {
  default = "prod"
}

# VPC
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "${var.environment}-vpc"
  }
}

# RDS database
resource "aws_db_instance" "postgres" {
  identifier     = "orders-db"
  engine         = "postgres"
  instance_class = "db.t3.micro"
  allocated_storage = 100
  
  db_name  = "orders"
  username = "admin"
  password = var.db_password # from tfvars
  
  multi_az = true # high availability
  backup_retention_period = 30
  
  tags = {
    Name = "${var.environment}-db"
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "${var.environment}-cluster"
  
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

output "database_endpoint" {
  value = aws_db_instance.postgres.endpoint
}
```

Apply:
```bash
terraform plan # preview changes
terraform apply # apply changes
terraform destroy # tear down
```

CloudFormation (AWS-native):
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Order Service Infrastructure

Parameters:
  Environment:
    Type: String
    Default: prod

Resources:
  OrderDatabase:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: postgres
      DBInstanceClass: db.t3.micro
      AllocatedStorage: 100
      DBName: orders
      MasterUsername: admin
      MasterUserPassword: !Sub '{{{{resolve:secretsmanager:db-password:SecretString:password}}}}'

  OrderServiceCluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: !Sub '${Environment}-cluster'

Outputs:
  DatabaseEndpoint:
    Value: !GetAtt OrderDatabase.Endpoint.Address
```

Benefits: infrastructure version control, reproducible deployments, automation.

Pitfall: IaC drift (manual changes outside code); always use IaC for changes.

---

### Q442: What is observability vs monitoring?

Monitoring: collect predefined metrics/logs/traces.

Observability: ability to understand system state from outputs (metrics, logs, traces, events).

Monitoring (reactive):
```
Metric: error_rate
Alert: IF error_rate > 5%, page on-call
Action: investigate and fix
```

Observability (proactive):
```
Question: "Why is error rate high?"
Trace: follow request through services, find slow span
Logs: examine detailed context
Metrics: correlate with infrastructure changes
Events: what changed (deployment, config)?
Answer: payment service slow due to database timeout
```

Implementation (O11y):
```java
@Service
public class ObservableOrderService {
  @Autowired MeterRegistry meterRegistry;
  @Autowired Tracer tracer;
  
  public Order createOrder(Order order) {
    Span span = tracer.spanBuilder("createOrder")
      .setAttribute("order.id", order.getId())
      .setAttribute("order.amount", order.getAmount())
      .startSpan();
    
    try (Scope scope = span.makeCurrent()) {
      // Emit metric
      meterRegistry.counter("orders.created", "status", "success").increment();
      
      // Trace nested calls
      Span dbSpan = tracer.spanBuilder("orderRepository.save")
        .setParent(Context.current().with(span))
        .startSpan();
      try {
        orderRepository.save(order);
      } finally {
        dbSpan.end();
      }
      
      return order;
    } catch (Exception e) {
      span.recordException(e);
      span.setStatus(StatusCode.ERROR);
      meterRegistry.counter("orders.created", "status", "error").increment();
      throw e;
    } finally {
      span.end();
    }
  }
}
```

Benefit: faster debugging, proactive issue detection, system understanding.

Pitfall: observability overhead (sampling helps); data retention cost.

---

### Q443: What is GitOps and declarative deployment?

GitOps: Git as source of truth; declarative infrastructure/config synced to cluster.

Tool: ArgoCD (Kubernetes)

```
GitHub repo:
└── manifests/
    ├── order-service-deployment.yaml
    ├── service.yaml
    └── configmap.yaml

ArgoCD polls GitHub every 3 minutes
If repo changed: automatically sync to cluster
```

order-service-deployment.yaml:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: order-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: order-service
  template:
    metadata:
      labels:
        app: order-service
    spec:
      containers:
      - name: order-service
        image: docker.io/myrepo/order-service:v1.2.0
```

ArgoCD Application:
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: order-service-app
spec:
  project: default
  source:
    repoURL: https://github.com/company/infra
    path: manifests/order-service
    targetRevision: main
  destination:
    server: https://kubernetes.default.svc
    namespace: production
  syncPolicy:
    automated:
      prune: true # delete resources not in Git
      selfHeal: true # revert manual changes
```

Workflow:
```
1. Developer commits new version to Git
2. ArgoCD detects change
3. Deploys to cluster automatically
4. If someone manually changes pod, ArgoCD reverts
```

Benefit: entire infrastructure at Git commit (reviewable, auditable), easy rollback.

Pitfall: secrets in Git (use sealed secrets or external vault).

---

### Q444: What are chaos engineering and resilience testing?

Chaos engineering: intentionally inject failures to find weaknesses.

Tools: Chaos Toolkit, Gremlin, LitmusChaos

Example (kill random pods):
```yaml
apiVersion: litmuschaos.io/v1alpha1
kind: ChaosEngine
metadata:
  name: pod-delete-chaos
spec:
  engineState: 'active'
  appinfo:
    appns: 'default'
    applabel: 'app=order-service'
  experiments:
  - name: pod-delete
    spec:
      components:
        env:
        - name: TOTAL_CHAOS_DURATION
          value: '30' # 30 seconds
        - name: CHAOS_INTERVAL
          value: '10' # every 10 seconds
        - name: REPLICAS
          value: '3'
```

Verify resilience:
```java
@SpringBootTest
public class ChaosResilienceTest {
  @Autowired OrderService orderService;
  @Autowired CircuitBreaker orderCB;
  
  @Test
  public void testOrderServiceWithPodFailure() throws Exception {
    // Start chaos: kill random pods every 10s for 30s
    chaosEngine.startChaos("pod-delete");
    
    // Application continues functioning (failing gracefully)
    for (int i = 0; i < 10; i++) {
      Order order = orderService.createOrder(new Order(...));
      assertThat(order).isNotNull(); // should succeed or gracefully degrade
      Thread.sleep(2000);
    }
    
    // After chaos stops, verify full recovery
    chaosEngine.stopChaos();
    Order order = orderService.createOrder(new Order(...));
    assertThat(order.getStatus()).isEqualTo("PENDING");
  }
}
```

Network failure injection:
```yaml
apiVersion: litmuschaos.io/v1alpha1
kind: ChaosEngine
metadata:
  name: network-latency-chaos
spec:
  experiments:
  - name: network-latency
    spec:
      components:
        env:
        - name: NETWORK_LATENCY # add 100ms latency
          value: '100'
        - name: TOTAL_CHAOS_DURATION
          value: '120'
```

Benefits: discover failure modes before production, build resilience, confidence.

Pitfall: chaos can cause issues in shared environments; use isolated staging.

---

### Q445: What is API versioning and backward compatibility?

API versioning: manage breaking changes without breaking clients.

Strategies:

URL path versioning:
```
GET /api/v1/orders/{id} → OrderV1DTO
GET /api/v2/orders/{id} → OrderV2DTO (new fields)
```

Header versioning:
```
GET /api/orders/{id}
Accept-Version: 1
```

Query parameter:
```
GET /api/orders/{id}?version=2
```

Backward compatibility (avoid breaking changes):

Additive change (safe):
```java
// v1
class Order {
  Long id;
  String status;
}

// v2 - add optional field
class Order {
  Long id;
  String status;
  LocalDateTime createdAt; // optional, default null
}
```

Rename field (breaking):
```java
// v1
class Order {
  String status;
}

// v2 - rename to orderStatus
class Order {
  String orderStatus; // breaks clients expecting 'status'
}

// Solution: support both (deprecation period)
class Order {
  @JsonProperty("status")
  @Deprecated // clients should use orderStatus
  String statusOld;
  
  @JsonProperty("orderStatus")
  String status; // new field
}
```

Response wrapping (versioning container):
```java
// v1
{
  "id": 1,
  "status": "PENDING"
}

// v2 - add metadata
{
  "data": {
    "id": 1,
    "status": "PENDING"
  },
  "apiVersion": "2.0",
  "timestamp": "2024-01-15T10:30:00Z"
}

// Solution: version response envelope
class ApiResponse<T> {
  T data;
  String apiVersion;
}
```

Deprecation strategy:
```java
@Deprecated(since = "2.0", forRemoval = true)
@GetMapping("/v1/orders/{id}")
public Order getOrderV1(@PathVariable Long id) {
  return getOrderV2(id); // delegate to v2
}

@GetMapping("/v2/orders/{id}")
public Order getOrderV2(@PathVariable Long id) {
  return orderService.getOrder(id);
}
```

Benefit: evolve API safely, support multiple client versions.

Pitfall: maintaining multiple versions increases complexity; sunset old versions eventually.

---

### Q446: What is finalization vs resource management in Java?

Finalization (deprecated): cleanup when object garbage-collected.

Pitfall:
- Unpredictable timing (GC not guaranteed)
- Performance impact (finalizer threads)
- Exception suppression (errors in finalizer swallowed)

```java
class Resource {
  @Override
  protected void finalize() throws Throwable {
    try {
      // cleanup
    } finally {
      super.finalize();
    }
  }
}
```

Try-with-resources (recommended):
```java
try (Connection conn = dataSource.getConnection()) {
  // use connection
  PreparedStatement stmt = conn.prepareStatement("SELECT * FROM orders");
  // ...
} // automatically closed (even if exception thrown)
```

Implement AutoCloseable:
```java
class ManagedResource implements AutoCloseable {
  private Connection connection;
  
  public ManagedResource(Connection connection) {
    this.connection = connection;
  }
  
  @Override
  public void close() throws Exception {
    connection.close();
  }
}

// Usage
try (ManagedResource resource = new ManagedResource(conn)) {
  // use resource
} // automatically closed
```

Cleaner API (Java 9+):
```java
class OffHeapMemory {
  private static final Cleaner cleaner = Cleaner.create();
  
  private final long address;
  private final int size;
  private final Cleanable cleanable;
  
  public OffHeapMemory(int size) {
    this.address = allocate(size);
    this.size = size;
    this.cleanable = cleaner.register(this, () -> free(address));
  }
  
  // cleanable runs when GC collects this object
}
```

Benefit: guaranteed cleanup (try-with-resources), predictable timing.

Pitfall: finalize() still used in legacy code; migrate to try-with-resources.

---

### Q447: What is supplier pattern and lazy initialization?

Supplier: defers computation until needed.

```java
// Eager (computed immediately)
Order order = expensiveOrderLookup(); // blocks

// Lazy (computed on demand)
Supplier<Order> orderSupplier = () -> expensiveOrderLookup();
Order order = orderSupplier.get(); // computed when called
```

Example (lazy bean):
```java
@Bean
@Lazy
public ExpensiveService expensiveService() {
  return new ExpensiveService(); // not instantiated until first use
}

@Component
public class OrderService {
  @Autowired @Lazy ExpensiveService service; // supplier injected
  
  public void process() {
    service.doWork(); // service instantiated on first call (or explicit get)
  }
}
```

Lazy fields:
```java
class OrderCache {
  private Supplier<List<Order>> orders = Suppliers.memoizeWithExpiration(
    () -> orderRepository.findAll(),
    10, TimeUnit.MINUTES
  );
  
  public List<Order> getOrders() {
    return orders.get(); // cached for 10 minutes
  }
}
```

Optional with supplier:
```java
Order order = orderRepository.findById(1L).orElseGet(() -> {
  log.warn("Order not found, creating default");
  return new Order(1L, 0.0, "UNKNOWN");
});
```

Benefit: defers expensive operations, improves startup time, optional computation.

Pitfall: unclear when supplier computed; document expectations.

---

### Q448: What is bulkhead pattern (thread pool isolation)?

Bulkhead: isolate resources (prevent one failure from cascading).

Example (payment service timeout → exhausts thread pool → affects other services):
```
Before bulkhead:
- Thread pool: 100 threads
- Payment service slow, holds 90 threads
- Other services starved (only 10 threads left)
- Request queue builds up, users timeout

After bulkhead:
- Thread pool: 100 threads
- Core pool: 50 threads for common requests
- Payment service gets isolated 30 threads
- Notification service gets isolated 20 threads
- If payment hangs, only those 30 threads affected
```

Resilience4j bulkhead:
```java
@Service
public class OrderService {
  @Autowired PaymentClient paymentClient;
  
  @Bulkhead(name = "paymentService", type = Bulkhead.Type.THREADPOOL)
  public Payment chargeWithIsolation(Order order) {
    return paymentClient.charge(order);
  }
}
```

Configuration:
```yaml
resilience4j:
  bulkhead:
    instances:
      paymentService:
        maxConcurrentCalls: 30
        maxWaitDuration: 10s
        threadPoolSize: 30
      notificationService:
        maxConcurrentCalls: 20
        maxWaitDuration: 5s
        threadPoolSize: 20
```

Semaphore-based (no thread pool, lighter):
```yaml
resilience4j:
  bulkhead:
    instances:
      paymentService:
        maxConcurrentCalls: 30
        maxWaitDuration: 10s
        type: semaphore # lighter than threadpool
```

Benefit: fault isolation, prevents cascading failures.

Pitfall: thread pool overhead; use semaphore for lightweight calls.

---

### Q449: What is event-driven architecture and event sourcing integration?

Event-driven: services communicate via events (asynchronous, decoupled).

```
Order Service publishes:
  → OrderCreatedEvent
  → OrderPaidEvent
  → OrderShippedEvent

Subscribers:
  → Inventory Service (reserves stock)
  → Notification Service (sends email)
  → Analytics Service (records metric)
```

Implementation (Spring ApplicationEventPublisher):
```java
@Entity
public class Order {
  @Id private Long id;
  private String status;
  
  public static Order create(Long userId, double amount) {
    Order order = new Order(userId, amount, "PENDING");
    order.recordEvent(new OrderCreatedEvent(order.getId(), order.getUserId()));
    return order;
  }
  
  private List<DomainEvent> domainEvents = new ArrayList<>();
  
  public void recordEvent(DomainEvent event) {
    domainEvents.add(event);
  }
  
  public List<DomainEvent> getDomainEvents() {
    return new ArrayList<>(domainEvents);
  }
  
  public void clearDomainEvents() {
    domainEvents.clear();
  }
}

@Service
public class OrderService {
  @Autowired OrderRepository orderRepository;
  @Autowired ApplicationEventPublisher eventPublisher;
  
  @Transactional
  public Order createOrder(CreateOrderRequest request) {
    Order order = Order.create(request.getUserId(), request.getAmount());
    Order saved = orderRepository.save(order);
    
    // Publish domain events
    saved.getDomainEvents().forEach(eventPublisher::publishEvent);
    saved.clearDomainEvents();
    
    return saved;
  }
}

@Component
public class OrderEventListener {
  @EventListener
  public void onOrderCreated(OrderCreatedEvent event) {
    log.info("Order created: {}", event.getOrderId());
    // Trigger inventory reservation, send notification, etc.
  }
}
```

Event sourcing integration:
```java
// Store events in table
@Entity
public class OrderEvent {
  @Id private UUID eventId;
  private Long orderId;
  private String eventType; // ORDER_CREATED, ORDER_PAID
  @Column(columnDefinition = "JSON") private String data;
  private LocalDateTime timestamp;
}

// Rebuild state from events
public Order rebuildOrderFromEvents(Long orderId) {
  List<OrderEvent> events = eventRepository.findByOrderIdOrderByTimestamp(orderId);
  Order order = new Order();
  
  for (OrderEvent event : events) {
    switch (event.getEventType()) {
      case "ORDER_CREATED":
        OrderCreatedEvent created = objectMapper.readValue(event.getData(), OrderCreatedEvent.class);
        order.setId(created.getOrderId());
        order.setStatus("PENDING");
        break;
      case "ORDER_PAID":
        order.setStatus("CONFIRMED");
        break;
      case "ORDER_SHIPPED":
        order.setStatus("SHIPPED");
        break;
    }
  }
  return order;
}
```

Benefit: event history (audit trail), asynchronous processing, decoupling.

Pitfall: eventual consistency (events propagate asynchronously); handle duplicates (idempotency).

---

### Q450: What is system design trade-offs summary?

Key trade-offs in microservices architecture:

Consistency vs Availability (CAP theorem):
- Strong consistency (ACID): slow (locks), unavailable if network partitioned
- Eventual consistency (BASE): fast, available, but temporary inconsistency

Monolith vs Microservices:
- Monolith: simpler deployment, harder scaling, coupled
- Microservices: complex ops, independent scaling, decoupled

Synchronous vs Asynchronous:
- Sync (REST): immediate response, coupling, blocking
- Async (events): decoupled, eventual consistency, complex debugging

Caching vs Freshness:
- More cache: fast, stale data, cache invalidation complexity
- Less cache: slow, fresh data, database overload

Database per Service vs Shared:
- Separate: independent scaling, data consistency complexity, joins hard
- Shared: easier queries, scaling bottleneck, coupling

Vertical vs Horizontal Scaling:
- Vertical (bigger machine): simpler, bottleneck, expensive
- Horizontal (more machines): complex ops, load balancing, distributed systems

Example trade-off decision:
```
Requirement: Low latency order lookup ($)
Option 1: Add cache (Redis)
  ✓ latency 10ms → 1ms (fast)
  ✗ cache invalidation complexity
  ✗ extra infrastructure cost

Option 2: Add database index
  ✓ latency 100ms → 50ms (acceptable)
  ✓ simple, no cache invalidation
  ✗ slower than cache

Option 3: Denormalize data (pre-compute aggregates)
  ✓ latency 100ms → 5ms
  ✓ no cache invalidation
  ✗ storage duplication, batch jobs to denormalize

Decision: Denormalize + selective caching (hot data)
```

Benefit: conscious design decisions, understand consequences.

Pitfall: no single best architecture; depends on requirements, team, constraints.

---

## Q451–Q500: Query Optimization, Advanced Patterns & Cloud Architecture

### Q451: What is N+1 query problem and solutions?

N+1 problem: fetch parent entity, then iterate and fetch each child separately (N queries instead of 1).

```java
// ANTI-PATTERN: N+1 queries
List<Order> orders = orderRepository.findAll(); // 1 query
for (Order order : orders) {
  List<OrderItem> items = itemRepository.findByOrderId(order.getId()); // N queries (one per order)
  order.setItems(items);
}
```

Solutions:

Eager loading (JOIN):
```java
@Entity
public class Order {
  @OneToMany(fetch = FetchType.EAGER) // EAGER load items with order
  private List<OrderItem> items;
}

// Query: SELECT o.* FROM orders o LEFT JOIN order_items i ON o.id = i.order_id
List<Order> orders = orderRepository.findAll(); // 1 query (includes items)
```

@EntityGraph (selective eager loading):
```java
@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {
  @EntityGraph(attributePaths = {"items", "customer"})
  List<Order> findAll();
}
```

Batch loading:
```java
List<Order> orders = orderRepository.findAll();
Long[] orderIds = orders.stream().map(Order::getId).toArray(Long[]::new);
Map<Long, List<OrderItem>> itemsByOrderId = itemRepository.findByOrderIdIn(orderIds)
  .stream()
  .collect(Collectors.groupingBy(OrderItem::getOrderId));

orders.forEach(o -> o.setItems(itemsByOrderId.get(o.getId()))); // no DB queries
```

Custom query:
```java
@Query("SELECT o FROM Order o LEFT JOIN FETCH o.items WHERE o.id IN :ids")
List<Order> findWithItems(@Param("ids") List<Long> orderIds);
```

Benefit: reduces query count from O(N) to O(1).

Pitfall: EAGER loading can be slow (unnecessary joins); profile and use selectively.

---

### Q452: What is query optimization with EXPLAIN ANALYZE?

EXPLAIN ANALYZE: profiling tool showing query execution plan.

PostgreSQL:
```sql
EXPLAIN ANALYZE
SELECT * FROM orders WHERE user_id = 123;

-- Output:
-- Seq Scan on orders (cost=0.00..45.00 rows=1 width=100)
--   Filter: (user_id = 123)
--   Planning Time: 0.15 ms
--   Execution Time: 2.35 ms
--
-- Interpretation: Sequential scan (slow), filters 1 row, 2.35ms execution
```

Add index:
```sql
CREATE INDEX idx_orders_user_id ON orders(user_id);

EXPLAIN ANALYZE
SELECT * FROM orders WHERE user_id = 123;

-- Output:
-- Index Scan using idx_orders_user_id (cost=0.28..8.29 rows=1 width=100)
--   Index Cond: (user_id = 123)
--   Execution Time: 0.12 ms
--
-- Much faster: index scan (0.12ms vs 2.35ms)
```

Composite index:
```sql
CREATE INDEX idx_orders_user_status ON orders(user_id, status);

EXPLAIN ANALYZE
SELECT * FROM orders WHERE user_id = 123 AND status = 'PENDING';

-- Index Scan using idx_orders_user_status (cost=0.28..4.15 rows=1 width=100)
--   Index Cond: (user_id = 123 AND status = 'PENDING')
--   Execution Time: 0.10 ms
```

Common issues:

Sequential scan (no index): add index
```
Seq Scan on orders (cost=0.00..45000.00 rows=1000000 width=100)
```

Nested loop join (expensive): add index on join column
```
Nested Loop (cost=0.28..1000000.00 rows=100000 width=200)
  -> Seq Scan on orders
  -> Index Scan on order_items (via nested loop)
```

Benefit: data-driven optimization, measurable improvement.

Pitfall: too many indexes (slows writes); monitor query patterns.

---

### Q453: What is partitioning strategies (range, list, hash)?

Partitioning: split large table across partitions for faster queries, scalability.

Range partitioning (by date):
```sql
CREATE TABLE orders (
  id BIGINT PRIMARY KEY,
  user_id BIGINT,
  amount DECIMAL,
  created_at DATE
) PARTITION BY RANGE (YEAR(created_at)) (
  PARTITION p2023 VALUES LESS THAN (2024),
  PARTITION p2024 VALUES LESS THAN (2025),
  PARTITION p2025 VALUES LESS THAN (2026),
  PARTITION pmax VALUES LESS THAN MAXVALUE
);

-- Query on 2024 orders: only searches p2024 partition
SELECT * FROM orders WHERE created_at >= '2024-01-01' AND created_at < '2025-01-01';
```

List partitioning (by region):
```sql
CREATE TABLE orders (
  id BIGINT PRIMARY KEY,
  region VARCHAR(50),
  amount DECIMAL
) PARTITION BY LIST (region) (
  PARTITION pus VALUES IN ('US', 'CA', 'MX'),
  PARTITION peu VALUES IN ('UK', 'DE', 'FR'),
  PARTITION pasia VALUES IN ('JP', 'CN', 'IN')
);
```

Hash partitioning (distribute by hash):
```sql
CREATE TABLE orders (
  id BIGINT PRIMARY KEY,
  user_id BIGINT,
  amount DECIMAL
) PARTITION BY HASH (user_id) PARTITIONS 10;

-- Rows distributed across 10 partitions based on user_id hash
```

Benefit: faster queries (scan fewer partitions), easier archival (drop old partitions).

Pitfall: resharding cost, cross-partition queries slow, partition key choice critical.

---

### Q454: What is database connection pooling tuning?

Connection pooling: reuse connections (avoid expensive creation).

HikariCP tuning:
```yaml
spring:
  datasource:
    hikari:
      minimumIdle: 5 # idle connections to keep alive
      maximumPoolSize: 20 # max concurrent connections
      idleTimeout: 600000 # 10 min before closing idle
      maxLifetime: 1800000 # 30 min max lifetime
      connectionTimeout: 30000 # 30 sec to acquire connection
      leakDetectionThreshold: 60000 # detect leaks > 60s
      validationQuery: "SELECT 1" # test connection on borrow
```

Tuning formula:
```
connections = ((core_count * 2) + effective_spindle_count)
Example: 8 cores, 1 disk → connections = (8 * 2) + 1 = 17
```

Monitor:
```java
@Component
public class ConnectionPoolMonitor {
  @Autowired HikariDataSource dataSource;
  
  @Scheduled(fixedRate = 60000)
  public void logPoolStats() {
    HikariPoolMXBean mxBean = dataSource.getHikariPoolMXBean();
    log.info("Active: {}, Idle: {}, Pending: {}", 
      mxBean.getActiveConnections(),
      mxBean.getIdleConnections(), 
      mxBean.getPendingThreads());
  }
}
```

Detect leaks:
```yaml
leakDetectionThreshold: 60000 # log warning if connection not returned > 60s
```

Common issue: connection exhaustion
```
Error: Unable to get a connection, timeout after 30 seconds
Problem: maxPoolSize too small OR connection leak
Solution: increase maxPoolSize OR find leaks (ensure close())
```

Benefit: optimal resource usage, better throughput.

Pitfall: tuning requires testing; different workloads need different settings.

---

### Q455: What is read replicas for scaling reads?

Read replicas: slave databases for read-only queries, master for writes.

```
Master (writes): 100 QPS write
Replica1 (reads): 1000 QPS read
Replica2 (reads): 1000 QPS read

Total read capacity: 2000 QPS (2x replicas)
Total write capacity: 100 QPS (single master bottleneck)
```

Spring configuration:
```java
@Configuration
public class RoutingDataSourceConfig {
  @Bean
  public DataSource dataSource() {
    AbstractRoutingDataSource router = new AbstractRoutingDataSource() {
      @Override
      protected Object determineCurrentLookupKey() {
        return TransactionSynchronizationManager.isCurrentTransactionReadOnly() 
          ? "slave" : "master";
      }
    };
    
    Map<Object, Object> sources = Map.of(
      "master", masterDataSource(),
      "slave", slaveDataSource()
    );
    router.setTargetDataSources(sources);
    return router;
  }
  
  private DataSource masterDataSource() {
    return DataSourceBuilder.create()
      .url("jdbc:mysql://master:3306/orders")
      .username("root")
      .password("secret")
      .build();
  }
  
  private DataSource slaveDataSource() {
    return DataSourceBuilder.create()
      .url("jdbc:mysql://slave:3306/orders")
      .username("root")
      .password("secret")
      .build();
  }
}

@Service
public class OrderService {
  @Transactional(readOnly = true) // routes to slave
  public Order getOrder(Long id) {
    return orderRepository.findById(id);
  }
  
  @Transactional // routes to master
  public void updateOrder(Order order) {
    orderRepository.save(order);
  }
}
```

Replication lag: slave lags master (asynchronous replication)
```
T0: Master writes order status = 'SHIPPED'
T1: Slave reads (still sees old status) → stale read
T2: Slave replicates write (lag ~100ms)
T3: Slave reads new status
```

Handle replication lag:
```java
@Service
public class OrderService {
  @Transactional(readOnly = true)
  public Order getOrderWithConsistency(Long id) {
    // For writes, immediately read from master (ensure consistency)
    Order order = masterRepository.findById(id);
    
    // For eventual consistency reads, use slave
    return slaveRepository.findById(id);
  }
}
```

Benefit: read scaling, high availability (failover to replica if master down).

Pitfall: replication lag (stale reads), failover complexity, writes still bottlenecked.

---

### Q456: What is full-text search (Elasticsearch)?

Full-text search: find documents matching keywords (not exact match).

Example:
```
Document: "Spring Boot Microservices Tutorial"
Query: "microservice" → matches (stemming: plural becomes singular)
Query: "spring" → matches
Query: "tutorial" → matches
```

Elasticsearch query:
```java
@Configuration
public class ElasticsearchConfig {
  @Bean
  public ElasticsearchOperations elasticsearchOperations(RestHighLevelClient client) {
    return new ElasticsearchRestTemplate(client);
  }
}

@Document(indexName = "orders")
@Data
public class OrderDocument {
  @Id private Long id;
  @Field(type = FieldType.Text, analyzer = "standard")
  private String description;
  @Field(type = FieldType.Keyword)
  private String status;
}

@Repository
public interface OrderSearchRepository extends ElasticsearchRepository<OrderDocument, Long> {
  List<OrderDocument> findByDescription(String keyword);
}

@Service
public class OrderSearchService {
  @Autowired OrderSearchRepository searchRepository;
  
  public List<OrderDocument> search(String keyword) {
    // Full-text search on description
    return searchRepository.findByDescription(keyword);
  }
  
  public List<OrderDocument> advancedSearch(String keyword, String status) {
    // Combined search
    Query query = new NativeSearchQueryBuilder()
      .withQuery(QueryBuilders.multiMatchQuery(keyword, "description", "status"))
      .withFilter(QueryBuilders.termQuery("status", status))
      .build();
    
    return searchRepository.search(query).stream()
      .map(SearchHit::getContent)
      .collect(Collectors.toList());
  }
}
```

Analyzers:
- Standard: lowercase, tokenize
- Keyword: exact match (no tokenization)
- Custom: custom stopwords, synonyms

Benefit: fast text search (inverted index), relevance scoring, facets.

Pitfall: Elasticsearch complexity (cluster, shards); managed services easier.

---

### Q457: What are advanced Java concurrency features?

StampedLock: stamped locks (optimistic/pessimistic).

```java
StampedLock lock = new StampedLock();
private long value;

public long readValue() {
  long stamp = lock.tryOptimisticRead(); // cheap read, no lock
  long result = value;
  if (!lock.validate(stamp)) { // check if modified during read
    stamp = lock.readLock(); // acquire read lock if invalid
    try {
      result = value;
    } finally {
      lock.unlockRead(stamp);
    }
  }
  return result;
}

public void updateValue(long val) {
  long stamp = lock.writeLock();
  try {
    value = val;
  } finally {
    lock.unlockWrite(stamp);
  }
}
```

VarHandle: atomic field access.

```java
private static final VarHandle ACCOUNT_BALANCE;

static {
  try {
    ACCOUNT_BALANCE = MethodHandles.lookup().findVarHandle(
      Account.class, "balance", long.class);
  } catch (NoSuchFieldException | IllegalAccessException e) {
    throw new ExceptionInInitializerError(e);
  }
}

public void transferFunds(long amount) {
  // Atomic operation (no lock, hardware-supported)
  ACCOUNT_BALANCE.compareAndSet(this, balance, balance + amount);
}
```

CompletableFuture: async tasks.

```java
CompletableFuture<Order> orderFuture = CompletableFuture.supplyAsync(() -> {
  return orderService.getOrder(1L);
})
.thenCompose(order -> paymentService.chargeAsync(order))
.thenCompose(payment -> notificationService.sendAsync(payment))
.exceptionally(ex -> {
  log.error("Error", ex);
  return null;
});

Order result = orderFuture.join(); // wait for completion
```

Benefit: fine-grained control, high concurrency, no locks.

Pitfall: complex debugging, deadlock risk (lock ordering).

---

### Q458: What is memory-mapped files (mmap)?

Memory-mapped files: map file to memory, access via pointers (faster than I/O).

```java
RandomAccessFile file = new RandomAccessFile("large-file.dat", "r");
FileChannel channel = file.getChannel();

// Map file to memory
MappedByteBuffer buffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());

// Access bytes without I/O
byte firstByte = buffer.get(0);
byte[] data = new byte[1024];
buffer.get(data); // read 1KB directly from memory

channel.close();
file.close();
```

Benefits: fast random access, large file handling, zero-copy.

Pitfall: memory pressure (entire file in RAM), platform-dependent.

---

### Q459: What is RSocket (reactive messaging)?

RSocket: binary protocol for reactive messaging (RPC over any transport).

```xml
<dependency>
  <groupId>io.rsocket</groupId>
  <artifactId>rsocket-core</artifactId>
</dependency>
<dependency>
  <groupId>io.rsocket</groupId>
  <artifactId>rsocket-transport-netty</artifactId>
</dependency>
```

Server:
```java
@Configuration
public class RSocketConfig {
  @Bean
  public RSocketServer rSocketServer() {
    return RSocketServer.create(socketAcceptor());
  }
  
  private SocketAcceptor socketAcceptor() {
    return (setup, sendingSocket) -> Mono.just(
      new RSocketResponder(orderService)
    );
  }
}

@RSocketController
public class OrderRSocketController {
  @Autowired OrderService orderService;
  
  @MessageMapping("orders.create") // async request-response
  public Mono<Order> createOrder(CreateOrderRequest request) {
    return Mono.fromCallable(() -> orderService.create(request));
  }
  
  @MessageMapping("orders.view") // server push stream
  public Flux<Order> streamOrders() {
    return orderService.streamOrders();
  }
}
```

Client:
```java
RSocket rSocket = RSocketConnector.connectTcp("localhost", 7000).block();

// Request-response
Mono<Order> orderMono = rSocket.requestResponse(
  DefaultPayload.create("{\"userId\":1}"),
  payload -> new Order(/* from payload */)
);

// Fire-and-forget
rSocket.fireAndForget(DefaultPayload.create("create-order")).block();

// Stream
Flux<Order> orders = rSocket.requestStream(
  DefaultPayload.create("{}"),
  payload -> new Order()
);
```

Benefits: low latency, bidirectional, multiplexing.

Pitfall: newer protocol (less maturity than REST); fewer tools/libraries.

---

### Q460: What are virtual threads (Project Loom)?

Virtual threads: lightweight threads (millions possible, not like platform threads).

```java
// Platform thread (OS-based): expensive, limited number
Thread platformThread = new Thread(() -> {
  System.out.println("Platform thread");
});
platformThread.start();

// Virtual thread (Java 19+)
Thread virtualThread = Thread.ofVirtual().start(() -> {
  System.out.println("Virtual thread");
});

// Create many virtual threads (millions possible)
for (int i = 0; i < 1_000_000; i++) {
  Thread.ofVirtual().start(() -> {
    // handle request
  });
}
```

Benefits: handles millions of concurrent connections, simplifies async code.

Example (servlet with virtual threads):
```java
// Traditional: thread pool limited, blocking
@RestController
public class OrderController {
  @GetMapping("/orders/{id}")
  public Order getOrder(@PathVariable Long id) {
    // blocks platform thread (few hundred available)
    return orderService.getOrder(id);
  }
}

// Virtual threads: can block freely (millions available)
server.tomcat.threads.max=10000 // can be much higher
```

Pitfall: not suitable for CPU-bound tasks (still limited by cores); good for I/O-bound.

---

### Q461: What is foreign data wrapper (FDW) in PostgreSQL?

FDW: query external data sources as PostgreSQL tables.

```sql
CREATE EXTENSION postgres_fdw;

CREATE SERVER order_warehouse
  FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host 'warehouse.example.com', dbname 'warehouse', port '5432');

CREATE USER MAPPING FOR current_user
  SERVER order_warehouse
  OPTIONS (user 'warehouse_user', password 'secret');

CREATE FOREIGN TABLE warehouse_orders (
  id BIGINT,
  amount DECIMAL,
  created_at TIMESTAMP
)
SERVER order_warehouse
OPTIONS (schema_name 'public', table_name 'orders');

-- Query external database transparently
SELECT * FROM warehouse_orders WHERE created_at > '2024-01-01';

-- Join local + external tables
SELECT l.id, l.amount, w.amount
FROM local_orders l
JOIN warehouse_orders w ON l.id = w.id;
```

Benefits: transparent access to external data, federated queries.

Pitfall: network latency (external queries slower); use for occasional access.

---

### Q462: What is distributed consensus (Raft, Paxos)?

Consensus: all nodes agree on shared state (critical for distributed systems).

Raft algorithm:
- Leader: handles writes, replicates to followers
- Followers: replicate leader's changes
- If leader fails, followers elect new leader

Election timeout: if follower doesn't hear leader in timeout, request votes.

Term: logical clock (term increases on election).

Log replication:
```
Leader: log entries [entry1, entry2]
Follower1: replicates entries
Follower2: replicates entries
Committed: when majority replicated
```

Tools: etcd (Raft), Consul (Raft), Zookeeper (Paxos).

Example (etcd for distributed config):
```bash
# Write key-value
etcdctl put /config/database/url "jdbc:mysql://db:3306/orders"

# All nodes see updated value
etcdctl get /config/database/url
# Output: jdbc:mysql://db:3306/orders
```

Benefit: fault-tolerant consensus, split-brain prevention.

Pitfall: consensus has performance cost (replication latency).

---

### Q463: What is blockchain-like patterns (merkle trees, immutable logs)?

Merkle tree: hash-based tree for efficient verification.

```
Root: hash(h1 + h2)
  h1: hash(h3 + h4)
  h2: hash(h5 + h6)
```

Append-only audit log (blockchain-inspired):
```java
@Entity
public class AuditLogEntry {
  @Id private UUID id;
  private String action;
  @Column(name = "prev_hash") private String previousHash;
  @Column(name = "curr_hash") private String currentHash;
  private LocalDateTime timestamp;
  
  public static String computeHash(String previousHash, String action) {
    String combined = previousHash + action + System.currentTimeMillis();
    return DigestUtils.sha256Hex(combined);
  }
}

@Service
public class ImmutableAuditService {
  @Autowired AuditLogRepository repository;
  
  @Transactional
  public void recordAction(String action) {
    AuditLogEntry lastEntry = repository.findLatest();
    String prevHash = lastEntry != null ? lastEntry.getCurrentHash() : "0";
    String currentHash = AuditLogEntry.computeHash(prevHash, action);
    
    repository.save(new AuditLogEntry(action, prevHash, currentHash));
  }
  
  public boolean isValid() {
    List<AuditLogEntry> entries = repository.findAllOrdered();
    String prevHash = "0";
    
    for (AuditLogEntry entry : entries) {
      String computed = AuditLogEntry.computeHash(prevHash, entry.getAction());
      if (!computed.equals(entry.getCurrentHash())) {
        return false; // tampering detected
      }
      prevHash = entry.getCurrentHash();
    }
    return true;
  }
}
```

Benefit: tamper detection, immutability verification.

Pitfall: performance cost (hashing), not needed unless audit is critical.

---

### Q464: What is database replication consistency models?

Replication consistency: how quickly replicas catch up.

Strong consistency (synchronous replication):
- Write to master, replicate to all slaves synchronously
- Commit only after all replicas ack
- Slow (wait for slowest replica)
- No stale reads

Eventual consistency (asynchronous replication):
- Write to master, replicate to slaves asynchronously
- Commit immediately (don't wait for replicas)
- Fast
- Stale reads possible

Causal consistency (hybrid):
- Write depends on previous write → replicate in order
- Causally related reads see writes in order
- Faster than strong, maintains causality

Implementation (Spring):
```java
@Service
public class OrderService {
  @Transactional // strong consistency (wait for replicas)
  public Order createOrderStrong(Order order) {
    return masterRepository.save(order);
  }
  
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public Order createOrderEventual(Order order) {
    // Write to master, don't wait for replication
    return masterRepository.saveAsync(order); // async operation
  }
  
  @Transactional(readOnly = true) // may read stale data
  public Order getOrderEventual(Long id) {
    return slaveRepository.findById(id);
  }
  
  @Transactional(readOnly = true) // fresh data
  public Order getOrderStrong(Long id) {
    return masterRepository.findById(id);
  }
}
```

Benefit: understand consistency guarantees, choose appropriate model.

Pitfall: strong consistency slow; eventual consistency is default (handle stale reads).

---

### Q465: What is data warehouse (OLTP vs OLAP)?

OLTP (Online Transaction Processing): operational database, optimized for writes.
- Many small transactions
- Normalized schema
- Row-oriented storage
- Example: MySQL, PostgreSQL

OLAP (Online Analytical Processing): data warehouse, optimized for reads.
- Few large queries
- Denormalized schema (star/snowflake)
- Column-oriented storage (Parquet, ORC)
- Example: Snowflake, BigQuery, Redshift

Example (order data warehouse):

OLTP (transactional):
```sql
-- Normalized
CREATE TABLE orders (id, user_id, amount, created_at);
CREATE TABLE order_items (id, order_id, product_id, quantity);
CREATE TABLE products (id, product_id, price);

-- Frequent writes: 1000 inserts/sec
INSERT INTO orders VALUES (...);
INSERT INTO order_items VALUES (...);
```

OLAP (analytics warehouse, ETL daily):
```sql
-- Denormalized (star schema)
CREATE TABLE fact_orders (
  order_id, user_id, product_id, quantity, amount,
  order_date, product_category, user_region
);

-- Typical query: product sales by region
SELECT user_region, SUM(amount)
FROM fact_orders
WHERE order_date >= '2024-01-01'
GROUP BY user_region;
```

ETL (Extract, Transform, Load):
```java
@Component
@Scheduled(cron = "0 0 2 * * ?") // daily at 2 AM
public class OrdersDwarehouse {
  @Autowired OrderRepository orderRepository;
  @Autowired WarehouseRepository warehouseRepository;
  
  public void loadOrdersToWarehouse() {
    List<Order> orders = orderRepository.findCreatedSince(LocalDate.now().minusDays(1));
    List<FactOrder> facts = orders.stream()
      .map(o -> new FactOrder(
        o.getId(), o.getUserId(), o.getProductId(),
        o.getQuantity(), o.getAmount(), o.getCreatedAt(),
        o.getProduct().getCategory(), o.getUser().getRegion()
      ))
      .collect(Collectors.toList());
    
    warehouseRepository.saveAll(facts);
  }
}
```

Benefit: fast analytics queries (hundreds of GB data), business intelligence.

Pitfall: ETL complexity, eventual consistency (daily data not real-time).

---

### Q466: What is sharding key design?

Sharding key: partition key determining shard assignment.

Good key (even distribution):
- user_id: user-based partitioning (most operations by user)
- customer_id: customer-based partitioning

Bad key (hotspot):
- status: few values (PENDING, COMPLETED) → uneven distribution
- date: temporal data (recent data concentrated in shards)
- region: geographic (some regions busier)

Hash selection:
```java
Long userId = 12345;
int shardId = (int) (Math.abs(userId.hashCode()) % NUM_SHARDS);
// shardId = 0-9 (for 10 shards)
```

Resharding (adding shards):
```
Old: 10 shards
New: 20 shards

For each key:
  Old shard = key % 10
  New shard = key % 20
  
Problem: old_shard != new_shard for most keys
Solution: migrate data (expensive, downtime risk)
```

Approach 1: consistent hashing (mitigates resharding):
```
Add new shard: only ~1/11 of keys rehashed (vs ~50% with modulo)
```

Approach 2: directory-based (explicit mapping):
```sql
CREATE TABLE shard_map (
  key BIGINT PRIMARY KEY,
  shard_id INT
);

SELECT shard_id FROM shard_map WHERE key = 12345;
```

Benefit: horizontal scaling, handle large datasets.

Pitfall: distributed joins difficult, cross-shard queries slow, resharding cost.

---

### Q467: What is zero-copy optimization (direct memory access)?

Zero-copy: avoid copying data between kernel and user space.

Traditional copy:
```
Network → Kernel buffer (1 copy)
       ↓
User program (2 copy: kernel → user stack)
       ↓
Application buffer (3 copy)
       ↓
Output (4 copy: user → kernel output)
= 4 copies total
```

Zero-copy (sendfile):
```
Network → Kernel buffer
       ↓
Output (direct: kernel → kernel, no user space)
= 0 copies to user space
```

Example (Java NIO):
```java
// Traditional I/O (copies)
FileInputStream fis = new FileInputStream("large-file.dat");
FileOutputStream fos = new FileOutputStream("output.dat");
byte[] buffer = new byte[8192];
int bytesRead;
while ((bytesRead = fis.read(buffer)) > 0) {
  fos.write(buffer, 0, bytesRead);
}

// Zero-copy NIO
FileChannel source = new FileInputStream("large-file.dat").getChannel();
FileChannel target = new FileOutputStream("output.dat").getChannel();
source.transferTo(0, source.size(), target); // zero-copy system call
```

Netty (zero-copy networking framework):
```java
public class ZeroCopyServerHandler extends ChannelInboundHandlerAdapter {
  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) {
    ByteBuf buf = (ByteBuf) msg;
    // Direct buffer (memory-mapped, zero-copy)
    byte[] data = new byte[buf.readableBytes()];
    buf.getBytes(0, data); // efficient, minimal copying
    
    ctx.writeAndFlush(Unpooled.wrappedBuffer(data));
  }
}
```

Benefit: reduced latency, lower CPU usage, throughput increase.

Pitfall: complex, platform-specific, not all I/O supports zero-copy.

---

### Q468: What is rate limiting per endpoint?

Different endpoints have different rate limits (API tier-based).

```java
@Configuration
public class RateLimitingConfig {
  @Bean
  public Map<String, RateLimit> endpointRateLimits() {
    return Map.of(
      "/api/orders", new RateLimit(100, Duration.ofMinutes(1)), // 100/min
      "/api/products", new RateLimit(1000, Duration.ofMinutes(1)), // 1000/min
      "/api/search", new RateLimit(10, Duration.ofMinutes(1)) // 10/min (expensive operation)
    );
  }
}

@Component
public class RateLimitFilter implements Filter {
  @Autowired Map<String, RateLimit> limits;
  @Autowired RateLimiterService limiter;
  
  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    String path = httpRequest.getRequestURI();
    String userId = httpRequest.getHeader("X-User-Id");
    
    RateLimit limit = limits.get(path);
    if (limit != null && !limiter.allowRequest(userId + ":" + path, limit)) {
      ((HttpServletResponse) response).setStatus(429);
      return;
    }
    chain.doFilter(request, response);
  }
}
```

Tiered rate limiting (by user tier):
```java
@Entity
public class User {
  Long id;
  String tier; // FREE, PREMIUM, ENTERPRISE
}

public int getLimit(User user, String endpoint) {
  return switch (user.getTier()) {
    case "FREE" -> 10; // 10 requests/min
    case "PREMIUM" -> 100;
    case "ENTERPRISE" -> 10000;
    default -> 1;
  };
}
```

Benefit: protect expensive endpoints, monetization (freemium model).

Pitfall: rate limits frustrate users; communicate clearly, provide upgrade path.

---

### Q469: What is eventual consistency conflict resolution?

Eventual consistency: replicas diverge, later converge (need conflict resolution).

Scenarios:

Last-write-wins (simple but lossy):
```
Replica A: order.status = PAID (time: 10:00)
Replica B: order.status = CANCELLED (time: 10:05)
Conflict: PAID and CANCELLED differ
Resolution: use timestamp → CANCELLED (10:05 > 10:00)
Risk: loses PAID status
```

Custom conflict resolver (merge):
```java
public class OrderConflictResolver {
  public Order resolve(Order a, Order b) {
    Order merged = new Order();
    merged.setId(a.getId());
    merged.setAmount(Math.max(a.getAmount(), b.getAmount())); // higher amount
    merged.setStatus(selectStatus(a.getStatus(), b.getStatus())); // status logic
    merged.setUpdatedAt(Instant.now());
    return merged;
  }
  
  private String selectStatus(String status1, String status2) {
    // Status precedence: SHIPPED > PAID > PENDING > CANCELLED
    int rank1 = statusRank(status1);
    int rank2 = statusRank(status2);
    return rank1 > rank2 ? status1 : status2;
  }
  
  private int statusRank(String status) {
    return switch (status) {
      case "SHIPPED" -> 4;
      case "PAID" -> 3;
      case "PENDING" -> 2;
      case "CANCELLED" -> 1;
      default -> 0;
    };
  }
}
```

Operational transformation (collaborative editing):
```
User A types: "Spring"
User B types: "Boot"
At same time

Resolved order:
A's op: insert "Spring" at position 0
B's op: insert "Boot" at position 0
Transformed A: insert "Spring" at position 0
Transformed B: insert "Boot" at position 6 (after "Spring")
Result: "SpringBoot"
```

Benefit: handle distributed updates, enable offline-first apps.

Pitfall: conflict resolution complex, application-specific.

---

### Q470: What is database Write-Ahead Logging (WAL)?

WAL: write changes to log before applying to database (durability).

```
1. Write to WAL (disk)
2. Ack to client (change is durable)
3. Apply to database (in-memory)
4. Periodically flush to disk (checkpoint)

If crash before checkpoint:
  Restart → replay WAL → recover state
```

PostgreSQL WAL:
```sql
-- Generate WAL entries
BEGIN;
INSERT INTO orders VALUES (...); -- WAL entry 1
UPDATE orders SET status='PAID'; -- WAL entry 2
COMMIT; -- WAL entry 3

-- If crash occurs, WAL replayed on restart
```

Checkpoint:
```
Checkpoint interval: 16MB WAL or 5 min (whichever first)
Before checkpoint: keep all WAL entries
After checkpoint: can discard old WAL (already applied)
```

Performance tuning:
```yaml
# PostgreSQL
wal_buffers: 16MB # in-memory WAL buffer
wal_writer_delay: 200ms # how often to flush WAL
max_wal_size: 4GB # max WAL size before checkpoint forced
```

Benefit: durability (ACID), crash recovery.

Pitfall: WAL I/O overhead (synchronous writes slow); balance with performance.

---

### Q471: What is request coalescing?

Request coalescing: merge duplicate simultaneous requests to avoid duplicate work.

Problem:
```
User A: GET /api/orders/1
User B: GET /api/orders/1
Result: 2 database queries (same data)
```

Solution (coalesce):
```
User A: GET /api/orders/1 → DB query starts
User B: GET /api/orders/1 → wait for A's result
Result: 1 database query (both get same result)
```

Implementation:
```java
@Component
public class RequestCoalescer {
  private Map<String, CompletableFuture<?>> pendingRequests = new ConcurrentHashMap<>();
  
  public <T> T coalesce(String key, Function<String, T> loader) {
    return (T) pendingRequests
      .computeIfAbsent(key, k -> CompletableFuture.supplyAsync(() -> loader.apply(k)))
      .join();
  }
}

@RestController
public class OrderController {
  @Autowired RequestCoalescer coalescer;
  @Autowired OrderService orderService;
  
  @GetMapping("/orders/{id}")
  public Order getOrder(@PathVariable Long id) {
    return coalescer.coalesce("order:" + id, 
      k -> orderService.getOrder(id));
  }
}
```

With caching:
```java
@Cacheable(value = "orders", key = "#id")
public Order getOrder(Long id) {
  return repository.findById(id);
}
```

Benefit: reduce duplicate database queries, improve throughput.

Pitfall: coalescing adds complexity; use strategically for expensive operations.

---

### Q472: What is lazy loading anti-pattern mitigation?

Lazy loading: fetch child entities on-demand (risk of N+1).

Anti-pattern:
```java
List<Order> orders = orderRepository.findAll(); // 1 query
for (Order order : orders) {
  order.getItems().size(); // N queries (N+1 problem)
}
```

Solutions:

Eager loading:
```java
@OneToMany(fetch = FetchType.EAGER)
private List<OrderItem> items;
```

@EntityGraph:
```java
@EntityGraph(attributePaths = "items")
List<Order> findAll();
```

Explicit fetch:
```java
@Query("SELECT o FROM Order o LEFT JOIN FETCH o.items")
List<Order> findAllWithItems();
```

Detached loading (after transaction):
```java
public List<Order> getOrdersWithItems() {
  List<Order> orders = orderRepository.findAll();
  for (Order order : orders) {
    Hibernate.initialize(order.getItems()); // force load before detach
  }
  return orders;
}
```

Benefit: prevent N+1 problem, predictable queries.

Pitfall: eager loading can fetch unnecessary data; profile and optimize.

---

### Q473: What is staleness and TTL (time-to-live)?

Staleness: how old cached data can be.

TTL strategy:
```java
@Cacheable(value = "orders", key = "#id", unless = "#result == null")
public Order getOrder(Long id) {
  return repository.findById(id);
}

cafeConfig:
  maximum-cache-age: 1h // stale after 1 hour
  refresh-after-write: 30m // refresh at 30 min
```

Soft expiry (refresh in background):
```java
@Service
public class CacheService {
  private Cache<String, OrderCache> cache = Caffeine.newBuilder()
    .refreshAfterWrite(30, TimeUnit.MINUTES) // soft expiry
    .expireAfterWrite(1, TimeUnit.HOURS) // hard expiry
    .build(key -> loadFromDb(key));
  
  public Order getOrder(Long id) {
    OrderCache cached = cache.get("order:" + id);
    if (cached.isStale()) {
      cache.invalidate("order:" + id); // hard refresh
    }
    return cached.getOrder();
  }
}
```

Benefit: cache efficiency, knowconsistency guarantees.

Pitfall: stale data can propagate (accept risk vs freshness).

---

### Q474: What is write combining?

Write combining: buffer writes, flush in batches (reduce I/O operations).

```java
@Service
public class BatchOrderProcessor {
  private List<Order> orderBuffer = new ArrayList<>();
  private final int BATCH_SIZE = 100;
  
  @Autowired OrderRepository repository;
  
  public void addOrder(Order order) {
    orderBuffer.add(order);
    if (orderBuffer.size() >= BATCH_SIZE) {
      flush();
    }
  }
  
  private void flush() {
    if (!orderBuffer.isEmpty()) {
      repository.saveAll(orderBuffer); // 1 batch insert vs 100 individual inserts
      orderBuffer.clear();
    }
  }
  
  @Scheduled(fixedRate = 1000) // flush every second if not full
  public void periodicFlush() {
    flush();
  }
}
```

Message queue batching:
```java
@KafkaListener(topics = "orders", groupId = "processor", batch-listener = true)
public void processBatch(List<Order> orders) {
  // Process 100 messages in 1 batch (vs 100 individual calls)
  orderRepository.saveAll(orders);
}
```

Benefit: reduce I/O operations, better throughput.

Pitfall: added latency (wait for batch to fill); use periodic flushing.

---

### Q475: What is type safety in REST APIs?

Type-safe REST using generated clients (OpenAPI/gRPC).

OpenAPI codegen:
```yaml
# openapi.yaml
openapi: 3.0.0
paths:
  /orders/{id}:
    get:
      parameters:
      - name: id
        in: path
        required: true
        schema:
          type: integer
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Order'
components:
  schemas:
    Order:
      type: object
      properties:
        id:
          type: integer
        status:
          type: string
          enum: [PENDING, COMPLETED, CANCELLED]
```

Generate client:
```bash
openapi-generator-cli generate -i openapi.yaml -g java -o ./client
```

Type-safe usage:
```java
// Generated code
OrderApi api = new OrderApi();
Order order = api.getOrder(1L); // type-safe, IDE autocomplete
String status = order.getStatus(); // know it's String, not Object
```

gRPC (strongly typed):
```protobuf
service OrderService {
  rpc GetOrder(GetOrderRequest) returns (Order);
}

message Order {
  int64 id = 1;
  string status = 2;
}
```

Generated Java:
```java
OrderServiceStub stub = OrderServiceGrpc.newStub(channel);
stub.getOrder(GetOrderRequest.newBuilder().setId(1).build(), 
  new StreamObserver<Order>() {
    public void onNext(Order order) {
      System.out.println(order.getStatus()); // type-safe
    }
  });
```

Benefit: catch errors at compile time, IDE support, documentation.

Pitfall: schema evolution complexity; coordinate changes between client/server.

---

### Q476: What is slow query handling and optimization?

Slow query log: identify queries exceeding threshold.

MySQL:
```sql
SET long_query_time = 0.5; -- log queries > 500ms
SET log_queries_not_using_indexes = ON;

SHOW SLOWLOG; -- view slow queries
```

Analysis:
```sql
SELECT query, count, avg_time, max_time
FROM mysql.slow_log
ORDER BY avg_time DESC
LIMIT 10;
```

Optimization steps:

1. Add index:
```sql
-- Slow query: SELECT * FROM orders WHERE user_id = 123;
CREATE INDEX idx_orders_user_id ON orders(user_id);
```

2. Rewrite query:
```sql
-- Slow (full table scan)
SELECT * FROM orders WHERE YEAR(created_at) = 2024;

-- Fast (uses index)
SELECT * FROM orders WHERE created_at >= '2024-01-01' AND created_at < '2025-01-01';
```

3. Denormalize:
```sql
-- Slow: JOIN 3 tables
SELECT o.id, p.name, SUM(oi.quantity)
FROM orders o
JOIN order_items oi ON o.id = oi.order_id
JOIN products p ON oi.product_id = p.id
GROUP BY o.id;

-- Fast: denormalized table (pre-aggregated)
SELECT * FROM order_summary WHERE created_at >= '2024-01-01';
```

Benefit: improve query performance, reduce database load.

Pitfall: optimization is iterative; profile before optimizing.

---

### Q477: What is index selectivity and covering indexes?

Index selectivity: % of rows matched by query.

High selectivity (good for index):
```sql
CREATE INDEX idx_orders_status ON orders(status);
-- Query: SELECT * FROM orders WHERE status = 'COMPLETED';
-- Selectivity: 0.1% (1000 out of 1M rows)
```

Low selectivity (bad for index):
```sql
CREATE INDEX idx_orders_active ON orders(is_active);
-- Query: SELECT * FROM orders WHERE is_active = true;
-- Selectivity: 90% (900K out of 1M rows)
-- Index scan slower than full table scan
```

Covering index: includes all columns for query (avoids table lookup).

```sql
-- Query: SELECT user_id, amount FROM orders WHERE created_at > '2024-01-01'

-- Standard index (slow: lookup table after index scan)
CREATE INDEX idx_orders_date ON orders(created_at);

-- Covering index (fast: all columns in index)
CREATE INDEX idx_orders_date_covering ON orders(created_at) INCLUDE (user_id, amount);
```

Execution:
```
Standard index:
1. Scan index (match created_at)
2. Lookup table for (user_id, amount) → N table lookups

Covering index:
1. Scan index (all columns available)
2. No table lookup needed
```

Benefit: faster queries, reduced table lookups.

Pitfall: covering indexes larger; trade disk space for speed.

---

### Q478: What is pagination patterns (offset vs cursor)?

Offset pagination (traditional):
```java
@GetMapping("/orders")
public ResponseEntity<Page<Order>> listOrders(
  @RequestParam(defaultValue = "0") int page,
  @RequestParam(defaultValue = "20") int size) {
  
  return ResponseEntity.ok(orderRepository.findAll(PageRequest.of(page, size)));
}
```

Issue: slow for large offsets (LIMIT 1000000, 20 scans 1M rows).

Cursor pagination (efficient):
```java
@GetMapping("/orders")
public ResponseEntity<List<Order>> listOrders(
  @RequestParam(required = false) String cursor,
  @RequestParam(defaultValue = "20") int size) {
  
  // Cursor: last order ID from previous page
  // WHERE id > cursor LIMIT 21 (size + 1 to detect "has more")
  Specification<Order> spec = (root, query, cb) -> {
    if (cursor != null) {
      return cb.greaterThan(root.get("id"), Long.parseLong(cursor));
    }
    return cb.conjunction();
  };
  
  List<Order> orders = orderRepository.findAll(spec, PageRequest.of(0, size + 1));
  
  String nextCursor = orders.size() > size ? 
    String.valueOf(orders.get(size).getId()) : null;
  
  return ResponseEntity.ok(new CursorPaginatedResponse(
    orders.subList(0, Math.min(size, orders.size())),
    nextCursor
  ));
}
```

Request: GET /orders?cursor=10&size=20
Response:
```json
{
  "items": [...20 items...],
  "nextCursor": "30"
}
```

Benefit: efficient pagination (constant time), prevents "concurrent modification" issues.

Pitfall: cursor opaque to clients (can't navigate to specific page); good for infinite scroll.

---

### Q479: What is query result caching invalidation?

Cache invalidation strategies:

Time-based:
```java
@Cacheable(value = "orders", key = "#userId", cacheManager = "cacheManager")
public List<Order> getOrders(Long userId) {
  return orderRepository.findByUserId(userId);
}

cacheConfig:
  caffeine.spec: expireAfterWrite=1h
```

Event-based (invalidate on change):
```java
@Service
public class OrderService {
  @Autowired ApplicationEventPublisher eventPublisher;
  @Autowired CacheManager cacheManager;
  
  @Transactional
  public Order createOrder(Order order) {
    Order saved = orderRepository.save(order);
    eventPublisher.publishEvent(new OrderCreatedEvent(saved.getUserId()));
    return saved;
  }
  
  @EventListener
  public void onOrderCreated(OrderCreatedEvent event) {
    // Invalidate user's order cache
    cacheManager.getCache("orders").evict("orders:" + event.getUserId());
  }
}
```

Tag-based invalidation:
```java
@Cacheable(value = "orders", key = "#userId", cacheManager = "tagAwareCacheManager")
public List<Order> getOrders(Long userId) {
  return orderRepository.findByUserId(userId);
}

// Tag: user:123
cacheManager.getCache("orders").evictIfPresent(new String[]{"user:123"});
```

Benefit: keep cache fresh without stale data.

Pitfall: invalidation timing (too early: recomputation, too late: stale data).

---

### Q480: What is distributed tracing improvements?

Tracing enhancements:

Correlation IDs (link related spans):
```java
@Component
public class CorrelationIdInterceptor implements ClientHttpRequestInterceptor {
  @Override
  public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) {
    String correlationId = MDC.get("X-Correlation-ID");
    request.getHeaders().add("X-Correlation-ID", correlationId);
    return execution.execute(request, body);
  }
}
```

Baggage (pass metadata):
```java
Baggage baggage = Baggage.builder()
  .put("user-id", userId)
  .put("request-type", "order-lookup")
  .build();

Tracer tracer = TracerProvider.get().get("app");
try (Scope scope = tracer.withBaggage(baggage)) {
  // baggage available in all child spans
}
```

Sampling strategies:

Probability sampling (10%):
```yaml
otel.traces.sampler: parentbased_traceidratio
otel.traces.sampler.arg: 0.1 # sample 10%
```

Adaptive sampling (based on metrics):
```java
public class AdaptiveSampler implements Sampler {
  public boolean shouldSample() {
    // Sample if error rate high (need more tracing for debugging)
    return errorRate > 5%;
  }
}
```

Benefit: reduced tracing overhead (sampling), better context propagation.

Pitfall: sampling can miss rare failures; test sampling strategy.

---

### Q481: What is bulkhead with timeout patterns?

Combine bulkhead (isolation) + timeout (abort slow operations).

```java
@Service
public class OrderService {
  @Bulkhead(name = "paymentService", type = Bulkhead.Type.THREADPOOL)
  @Timeout(name = "paymentService")
  public Payment charge(Order order) {
    // 1. Limited threads (bulkhead)
    // 2. Aborts after 5 seconds (timeout)
    return paymentClient.charge(order);
  }
}
```

Configuration:
```yaml
resilience4j:
  bulkhead:
    instances:
      paymentService:
        maxConcurrentCalls: 30
        maxWaitDuration: 10s
        threadPoolSize: 30
  timeout:
    instances:
      paymentService:
        timeoutDuration: 5s
        cancelRunningFuture: true
```

Fallback on failure:
```java
@Bulkhead(name = "paymentService", fallbackMethod = "chargeFallback")
@Timeout(name = "paymentService")
public Payment charge(Order order) {
  return paymentClient.charge(order);
}

public Payment chargeFallback(Order order, Exception e) {
  // Timeout or bulkhead rejection
  return new Payment(status = "PENDING_RETRY");
}
```

Benefit: prevents resource exhaustion, cascading failures.

Pitfall: timeout too short (false positives), too long (defeats purpose).

---

### Q482: What is request batching in APIs?

Request batching: combine multiple requests into single batch (reduce overhead).

GraphQL batch query:
```graphql
query {
  order1: order(id: 1) { id, status }
  order2: order(id: 2) { id, status }
  order3: order(id: 3) { id, status }
}
```

Custom batch API:
```java
@PostMapping("/batch")
public ResponseEntity<List<OrderResponse>> batch(@RequestBody BatchRequest request) {
  // Single request: multiple operations
  List<OrderResponse> responses = request.getOperations().stream()
    .map(op -> executeOperation(op))
    .collect(Collectors.toList());
  
  return ResponseEntity.ok(responses);
}

// Request:
{
  "operations": [
    {"action": "getOrder", "id": 1},
    {"action": "getOrder", "id": 2},
    {"action": "updateStatus", "id": 3, "status": "PAID"}
  ]
}

// Response:
[
  {"id": 1, "status": "PENDING"},
  {"id": 2, "status": "COMPLETED"},
  {"id": 3, "status": "PAID"}
]
```

Benefits: reduce HTTP overhead, fewer round-trips, better throughput.

Pitfall: single error can fail entire batch; use partial success responses.

---

### Q483: What is schema validation library?

Schema validation: validate JSON against schema.

JSONSchema:
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "userId": {
      "type": "integer",
      "minimum": 1
    },
    "amount": {
      "type": "number",
      "exclusiveMinimum": 0
    },
    "status": {
      "type": "string",
      "enum": ["PENDING", "COMPLETED", "CANCELLED"]
    }
  },
  "required": ["userId", "amount"]
}
```

ValidationUtil:
```java
@Component
public class SchemaValidator {
  private JsonSchema schema;
  
  @PostConstruct
  public void init() throws IOException {
    JsonNode schemaNode = objectMapper.readTree(getClass().getResource("/order-schema.json"));
    schema = JsonSchemaFactory.byDefault().getJsonSchema(schemaNode);
  }
  
  public void validate(Order order) throws ValidationException {
    JsonNode node = objectMapper.valueToTree(order);
    ProcessingReport report = schema.validate(node);
    if (!report.isSuccess()) {
      throw new ValidationException(report.toString());
    }
  }
}
```

Benefit: validate API inputs, catch invalid data early.

Pitfall: schema maintenance (keep in sync with code).

---

### Q484: What is service mesh observability improvements?

Service mesh (Istio) provides observability out-of-box.

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: order-service
spec:
  hosts:
  - order-service
  http:
  - match:
    - headers:
        user-type:
          exact: "premium"
    route:
    - destination:
        host: order-service
        port:
          number: 8080
        subset: v2 # route premium users to v2
      weight: 100
  - route:
    - destination:
        host: order-service
        subset: v1 # route others to v1
      weight: 100
```

Metrics (Prometheus):
```
istio_request_total{destination_service="order-service", response_code="200"}
istio_request_duration_milliseconds_bucket{destination_service="order-service"}
```

Kiali visualization (service mesh graph):
- Services: boxes
- Requests: arrows (thickness = traffic volume)
- Colors: error rates (red = high error)

Distributed tracing (Jaeger):
- Shows entire request path (order → payment → notification)
- Latency breakdown per service
- Error propagation

Benefit: unified observability, no code changes required.

Pitfall: service mesh overhead (sidecar proxies); not needed for small deployments.

---

### Q485: What is API deprecation and versioning strategy?

Deprecation timeline:

Phase 1: Announce (3 months)
```
API endpoint: GET /api/v1/orders/{id} [DEPRECATED]
Header: Deprecation: true
Link: </api/v2/orders/{id}>; rel="successor-version"
```

Phase 2: Support dual versions (6 months)
```
v1: /api/v1/orders/{id}
v2: /api/v2/orders/{id}
Both work for 6 months
```

Phase 3: v1 optional (3 months)
```
Added: X-API-Warn: "v1 deprecated, use v2"
```

Phase 4: Sunset (remove)
```
v1 returns 410 Gone
```

Implementation:
```java
@RestController
@RequestMapping("/api/v1/orders")
public class OrderControllerV1 {
  @GetMapping("/{id}")
  @Deprecated(since = "2.0", forRemoval = true)
  public ResponseEntity<Order> getOrder(@PathVariable Long id) {
    HttpHeaders headers = new HttpHeaders();
    headers.add("Deprecation", "true");
    headers.add("Link", "</api/v2/orders/{}; rel=\"successor-version\"");
    return ResponseEntity.ok().headers(headers).body(orderService.getOrder(id));
  }
}

@RestController
@RequestMapping("/api/v2/orders")
public class OrderControllerV2 {
  @GetMapping("/{id}")
  public ResponseEntity<Order> getOrder(@PathVariable Long id) {
    return ResponseEntity.ok(orderService.getOrder(id));
  }
}
```

Benefit: graceful migration path, avoid breaking clients.

Pitfall: maintaining multiple versions is costly; phase out aggressively.

---

### Q486: What is GraphQL for complex data fetching?

GraphQL: query language for APIs (request only needed fields).

Schema:
```graphql
type Order {
  id: ID!
  status: String!
  items: [OrderItem!]!
  customer: Customer!
}

type OrderItem {
  productId: ID!
  quantity: Int!
  price: Float!
}

type Query {
  order(id: ID!): Order
  orders(userId: ID!): [Order!]!
}

type Mutation {
  createOrder(input: CreateOrderInput!): Order!
  updateStatus(orderId: ID!, status: String!): Order!
}
```

Query (client requests only needed fields):
```graphql
query {
  order(id: 1) {
    id
    status
    items {
      productId
      quantity
    }
    customer {
      name
      email
    }
  }
}
```

Spring GraphQL setup:
```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-graphql</artifactId>
</dependency>
```

Resolver:
```java
@Component
public class OrderResolver {
  private final OrderService orderService;
  private final CustomerService customerService;
  
  @QueryMapping
  public Order order(@Argument Long id) {
    return orderService.getOrder(id);
  }
  
  @SchemaMapping
  public Customer customer(Order order) {
    return customerService.getCustomer(order.getCustomerId());
  }
}
```

Benefits: exact data fetching (no over-fetching), single endpoint, strongly typed.

Pitfall: GraphQL complexity; N+1 problem still exists (need batching/caching).

---

### Q487: What is health check endpoints and liveness/readiness?

Health endpoint (Spring Boot Actuator):
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,readiness,liveness
  endpoint:
    health:
      show-details: always
```

Liveness: is application alive?
```java
@Component
public class CustomLivenessChecker extends AbstractHealthIndicator {
  @Override
  protected void doHealthCheck(Health.Builder builder) {
    // Check if application logic is working
    if (isApplicationAlive()) {
      builder.up();
    } else {
      builder.down().withDetail("reason", "Background job frozen");
    }
  }
}
```

Readiness: can application handle traffic?
```java
@Component
public class CustomReadinessChecker extends AbstractHealthIndicator {
  @Override
  protected void doHealthCheck(Health.Builder builder) {
    // Check if all dependencies ready
    if (isDatabaseReady() && isCacheReady()) {
      builder.up();
    } else {
      builder.down().withDetail("reason", "Database not ready");
    }
  }
}
```

Kubernetes usage:
```yaml
livenessProbe:
  httpGet:
    path: /actuator/health/liveness
    port: 8080
  initialDelaySeconds: 30

readinessProbe:
  httpGet:
    path: /actuator/health/readiness
    port: 8080
  initialDelaySeconds: 5
```

Protocol: 200 OK = healthy, 503 Service Unavailable = unhealthy

Benefit: automatic pod restart/removal, traffic management.

Pitfall: false positives (restart cascades); accurate health checks essential.

---

### Q488: What is distributed transactions without 2PC?

Two-phase commit (2PC) is slow. Alternatives:

Saga pattern (orchestrated):
```
Order Service:
  → Create order (event)
  → Payment Service (async)
  → Inventory Service (async)
  
If payment fails:
  → Compensation: cancel order
  → Notification: inform customer
```

Implementation:
```java
@Service
public class OrderSagaOrchestrator {
  @Autowired OrderService orderService;
  @Autowired PaymentService paymentService;
  @Autowired InventoryService inventoryService;
  
  @Transactional
  public void createOrder(CreateOrderRequest request) {
    // Step 1
    Order order = orderService.createOrder(request);
    
    try {
      // Step 2
      Payment payment = paymentService.charge(order.getAmount());
      
      // Step 3
      inventoryService.reserveItems(order.getItems());
      
      // Success
      order.setStatus("CONFIRMED");
      orderService.save(order);
    } catch (PaymentException e) {
      // Compensation: rollback
      orderService.cancel(order.getId());
      throw e;
    } catch (InventoryException e) {
      // Compensation
      paymentService.refund(order.getId());
      orderService.cancel(order.getId());
      throw e;
    }
  }
}
```

Event sourcing approach (choreographed):
```
1. Create Order → OrderCreatedEvent published
2. Payment Service subscribed → charges → PaymentCompletedEvent
3. Inventory Service subscribed → reserves → InventoryReservedEvent
4. Order Service subscribed → confirms order
```

Implementation:
```java
@Service
public class OrderEventHandler {
  @EventListener
  public void onOrderCreated(OrderCreatedEvent event) {
    paymentService.chargeAsync(event.getOrderId(), event.getAmount());
  }
  
  @EventListener
  public void onPaymentCompleted(PaymentCompletedEvent event) {
    inventoryService.reserveAsync(event.getOrderId());
  }
  
  @EventListener
  public void onPaymentFailed(PaymentFailedEvent event) {
    orderService.cancelOrder(event.getOrderId());
  }
}
```

Benefit: avoids 2PC (faster), more scalable.

Pitfall: eventual consistency, complex compensation logic.

---

### Q489: What is observability data retention and cost management?

Observability data grows exponentially (metrics, logs, traces).

Cost breakdown:
- Logs: 10GB/day (~$100/month)
- Metrics: 1M time series (~$50/month)
- Traces: 10K traces/sec (~$200/month)

Strategies:

Sampling (reduce volume):
```yaml
# Traces
sampling-rate: 0.1 # keep 10%

# Logs
level: WARN # don't log DEBUG (verbose)

# Metrics
histogram-buckets: [0.01, 0.1, 1, 10] # fewer buckets
```

Retention tiers:
```
Hot (30 days): full resolution, fast queries
Warm (90 days): 1h aggregation, slower
Cold (1 year): daily aggregation, cheapest
```

Implementation:
```java
@Component
public class ObservabilityConfig {
  @Bean
  public TracerProvider tracerProvider() {
    SpanProcessor processor = new BatchSpanProcessor(
      OtlpGrpcSpanExporter.builder()
        .setEndpoint("http://jaeger:4317")
        .setTimeout(5, TimeUnit.SECONDS)
        .setSampler(new ProbabilitySampler(0.1)) // 10% sampling
        .build()
    );
    return SdkTracerProvider.builder()
      .addSpanProcessor(processor)
      .build();
  }
}
```

Benefit: reduce observability costs, maintain visibility.

Pitfall: over-aggressive sampling (miss rare failures), under-sampling (insufficient data).

---

### Q490: What is eventual consistency handling in APIs?

Eventual consistency: changes propagate asynchronously (temporary inconsistency).

Patterns:

Polling (client retries):
```java
@RestController
public class OrderController {
  @GetMapping("/orders/{id}")
  public ResponseEntity<Order> getOrder(@PathVariable Long id) {
    Order order = orderService.getOrder(id);
    
    // If order not fully processed, return 202 Accepted (not ready)
    if (order.getStatus().equals("PROCESSING")) {
      return ResponseEntity.accepted().body(order);
    }
    
    return ResponseEntity.ok(order);
  }
}

// Client polls until ready
while (true) {
  ResponseEntity<Order> response = restTemplate.getForEntity("/orders/1", Order.class);
  if (response.getStatusCode().is2xxSuccessful() && !response.getBody().isProcessing()) {
    break;
  }
  Thread.sleep(1000);
}
```

Webhooks (push notification):
```java
@Service
public class OrderService {
  @Autowired WebhookPublisher webhookPublisher;
  
  public void processOrder(Order order) {
    // Async processing
    CompletableFuture.runAsync(() -> {
      try {
        payment = chargePayment(order);
        order.setStatus("PAID");
        save(order);
        
        // Notify via webhook
        webhookPublisher.publish("order.paid", order);
      } catch (Exception e) {
        webhookPublisher.publish("order.failed", order);
      }
    });
  }
}

// Webhook consumer (client webhook endpoint)
@PostMapping("/webhooks/order")
public ResponseEntity<Void> onOrderEvent(@RequestBody WebhookPayload payload) {
  log.info("Order event: {}", payload.getEventType());
  return ResponseEntity.ok().build();
}
```

Causality tracking (version numbers):
```java
// POST /orders → { id: 1, version: 1, status: PENDING }
// Eventually changes to: { id: 1, version: 2, status: PAID }

@GetMapping("/orders/{id}")
public ResponseEntity<Order> getOrder(@PathVariable Long id, @RequestHeader(value = "Version") String expectedVersion) {
  Order order = orderService.getOrder(id);
  
  if (!order.getVersion().equals(expectedVersion)) {
    // Version mismatch: order changed
    return ResponseEntity.status(409).body(order); // Conflict
  }
  
  return ResponseEntity.ok(order);
}
```

Benefit: handle asynchronous systems, avoid blocking.

Pitfall: client complexity (polling/webhooks); require clear communication.

---

### Q491: What is API gateway routing strategies?

API gateway: single entry point, routes requests to backend services.

Path-based routing:
```yaml
spring:
  cloud:
    gateway:
      routes:
      - id: order-service
        uri: http://order-service:8080
        predicates:
        - Path=/api/orders/**
      
      - id: payment-service
        uri: http://payment-service:8081
        predicates:
        - Path=/api/payments/**
```

Header-based routing:
```yaml
- id: premium-service
  uri: http://premium-service:8080
  predicates:
  - Header=X-User-Tier,PREMIUM
      
- id: regular-service
  uri: http://regular-service:8080
  predicates:
  - Header=X-User-Tier,FREE
```

Weight-based (canary):
```yaml
- id: order-service-v1
  uri: http://order-service-v1:8080
  predicates:
  - Path=/api/orders/**
  metadata:
    weight: 90 # 90% traffic

- id: order-service-v2
  uri: http://order-service-v2:8080
  predicates:
  - Path=/api/orders/**
  metadata:
    weight: 10 # 10% traffic (canary)
```

Custom routing logic:
```java
@Component
public class CustomRouteLocator {
  @Bean
  public RouteLocator routes(RouteLocatorBuilder builder) {
    return builder.routes()
      .route(r -> r
        .path("/api/orders/**")
        .filters(f -> f.circuitBreaker(c -> c.setName("orderServiceCB")))
        .uri("http://order-service:8080"))
      .build();
  }
}
```

Benefit: single entry point, cross-cutting concerns (auth, logging, rate limiting).

Pitfall: gateway becomes bottleneck; ensure scalability (multiple instances).

---

### Q492: What is API contract enforcement?

Contract testing: ensure API changes don't break clients.

Consumer contract:
```java
@Test
public void testOrderServiceContract() {
  // Consumer expects GET /orders/1 → { id: 1, status: PENDING }
  OrderDTO order = client.getOrder(1L);
  assertThat(order.getId()).isEqualTo(1);
  assertThat(order.getStatus()).isEqualTo("PENDING");
}
```

Provider contract:
```java
@Test
public void testOrderEndpoint() {
  // Provider must match contract
  MockMvc mockMvc = MockMvcBuilders.standaloneSetup(orderController).build();
  mockMvc.perform(get("/orders/1"))
    .andExpect(status().isOk())
    .andExpect(jsonPath("$.id").value(1))
    .andExpect(jsonPath("$.status").value("PENDING"));
}
```

Compatibility flags (graceful changes):
```java
@GetMapping("/orders/{id}")
public OrderResponse getOrder(@PathVariable Long id, @RequestHeader(value = "Api-Version", required = false) String apiVersion) {
  Order order = orderService.getOrder(id);
  
  if ("1".equals(apiVersion)) {
    return new OrderV1Response(order.getId(), order.getStatus());
  } else {
    return new OrderV2Response(order.getId(), order.getStatus(), order.getCreatedAt());
  }
}
```

Benefit: prevent breaking changes, safe API evolution.

Pitfall: contract enforcement requires both parties (consumer + provider tightly coupled).

---

### Q493: What is external service fault tolerance?

External service failures: network timeout, service crash, rate limiting.

Retry with exponential backoff:
```java
@Service
public class PaymentClient {
  @Retry(maxAttempts = 3, backoff = @Backoff(delay = 1000, multiplier = 2))
  public Payment charge(Order order) {
    // Retry: 1s, 2s, 4s if fails
    return externalPaymentGateway.charge(order);
  }
}
```

Fallback:
```java
@CircuitBreaker(fallbackMethod = "chargeFallback")
public Payment charge(Order order) {
  return externalPaymentGateway.charge(order);
}

public Payment chargeFallback(Order order, Exception e) {
  // Queue for retry later
  retryQueue.add(new PaymentRetry(order));
  return new Payment(status = "PENDING_RETRY");
}
```

Timeout (abort slow requests):
```java
@Timeout(value = 5L, unit = TimeUnit.SECONDS)
public Payment charge(Order order) {
  // Abort if takes > 5 seconds
  return externalPaymentGateway.charge(order);
}
```

Health check (detect unavailability):
```java
@Component
public class PaymentGatewayHealthIndicator extends AbstractHealthIndicator {
  @Override
  protected void doHealthCheck(Health.Builder builder) {
    try {
      externalClient.ping();
      builder.up();
    } catch (Exception e) {
      builder.down().withDetail("reason", e.getMessage());
    }
  }
}
```

Benefit: resilience to external failures, graceful degradation.

Pitfall: too many retries cascade (thundering herd); use exponential backoff + jitter.

---

### Q494: What is resource pooling and object reuse?

Resource pooling: reuse expensive objects (connections, threads).

Connection pooling (HikariCP):
```yaml
spring.datasource.hikari:
  maximumPoolSize: 20 # reuse 20 connections
  minimumIdle: 5
  idleTimeout: 600000 # close idle after 10 min
```

Thread pooling:
```java
@Configuration
public class ThreadPoolConfig {
  @Bean
  public TaskExecutor taskExecutor() {
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(10);
    executor.setMaxPoolSize(50);
    executor.setQueueCapacity(100);
    executor.initialize();
    return executor;
  }
}
```

Object pooling (Apache Commons Pool):
```java
public class OrderServiceObjectPool {
  private ObjectPool<OrderProcessor> pool = new GenericObjectPool<>(
    new BasePooledObjectFactory<OrderProcessor>() {
      public OrderProcessor create() {
        return new OrderProcessor(); // expensive to create
      }
      
      public PooledObject<OrderProcessor> wrap(OrderProcessor obj) {
        return new DefaultPooledObject<>(obj);
      }
    },
    new GenericObjectPoolConfig<>().setMaxTotal(50)
  );
  
  public void processOrder(Order order) throws Exception {
    OrderProcessor processor = pool.borrowObject();
    try {
      processor.process(order);
    } finally {
      pool.returnObject(processor); // reuse
    }
  }
}
```

Benefit: reduces creation/destruction overhead, improves throughput.

Pitfall: pool exhaustion (all objects busy); monitor pool utilization.

---

### Q495: What is request deduplication and idempotency key?

Idempotency key: unique request identifier, safe to retry.

Implementation:
```java
@PostMapping("/orders")
public ResponseEntity<Order> createOrder(
  @RequestHeader("Idempotency-Key") String idempotencyKey,
  @RequestBody CreateOrderRequest request) {
  
  // Check if already processed
  IdempotentRequest existing = idempotencyKeyRepository.findByKey(idempotencyKey);
  if (existing != null) {
    return ResponseEntity.ok(existing.getResult());
  }
  
  // Process new request
  Order order = orderService.create(request);
  idempotencyKeyRepository.save(new IdempotentRequest(idempotencyKey, order));
  
  return ResponseEntity.status(201).body(order);
}
```

Client implementation:
```java
public Order createOrderWithIdempotency(CreateOrderRequest request) {
  String idempotencyKey = UUID.randomUUID().toString();
  
  for (int attempt = 0; attempt < 3; attempt++) {
    try {
      HttpHeaders headers = new HttpHeaders();
      headers.add("Idempotency-Key", idempotencyKey);
      
      HttpEntity<CreateOrderRequest> entity = new HttpEntity<>(request, headers);
      ResponseEntity<Order> response = restTemplate.postForEntity(
        "/orders", entity, Order.class);
      
      return response.getBody();
    } catch (Exception e) {
      if (attempt < 2) {
        Thread.sleep((long) Math.pow(2, attempt) * 1000); // exponential backoff
      } else {
        throw e;
      }
    }
  }
  return null;
}
```

Benefit: exactly-once semantics despite network failures, safe retries.

Pitfall: idempotency key storage (expensive); use TTL.

---

### Q496: What is async request-response patterns?

Traditional (synchronous request-response):
```
Client: POST /orders → wait
Server: process → 201 Created { order }
```

Async request-response (202 Accepted):
```
Client: POST /orders → immediate 202 Accepted { requestId: "req123" }
         poll GET /requests/req123 until complete

Server: background task processes order → updates status
```

Implementation:
```java
@PostMapping("/orders")
public ResponseEntity<AsyncResponse> createOrderAsync(@RequestBody CreateOrderRequest request) {
  String requestId = UUID.randomUUID().toString();
  
  // Queue for async processing
  asyncExecutor.submit(() -> {
    try {
      Order order = orderService.create(request);
      asyncRequestRepository.updateStatus(requestId, "COMPLETED", order);
    } catch (Exception e) {
      asyncRequestRepository.updateStatus(requestId, "FAILED", e.getMessage());
    }
  });
  
  return ResponseEntity
    .accepted()
    .location(URI.create("/requests/" + requestId))
    .body(new AsyncResponse(requestId, "Processing"));
}

@GetMapping("/requests/{requestId}")
public ResponseEntity<RequestStatus> getRequestStatus(@PathVariable String requestId) {
  AsyncRequest request = asyncRequestRepository.findById(requestId);
  
  if (request.getStatus().equals("COMPLETED")) {
    return ResponseEntity.ok(new RequestStatus(request.getStatus(), request.getResult()));
  } else if (request.getStatus().equals("PROCESSING")) {
    return ResponseEntity.accepted().body(new RequestStatus(request.getStatus(), null));
  } else {
    return ResponseEntity.status(500).body(new RequestStatus(request.getStatus(), request.getError()));
  }
}
```

Benefit: handle long-running operations, HTTP timeout avoidance.

Pitfall: client complexity (polling, state management).

---

### Q497: What is circuit breaker metrics and monitoring?

Monitor circuit breaker health:

Metrics:
```
circuit_breaker_calls_total{state="closed"} 1000
circuit_breaker_calls_total{state="open"} 50
circuit_breaker_calls_total{state="half_open"} 5

circuit_breaker_error_rate{service="payment"} 0.25 # 25% error rate
```

States tracking:
```java
@Component
public class CircuitBreakerMetrics {
  @Autowired MeterRegistry meterRegistry;
  
  public void recordCircuitBreakerState(String serviceName, CircuitBreaker.State state) {
    meterRegistry.gauge("circuit_breaker_state", 
      Tags.of("service", serviceName, "state", state.toString()),
      () -> state.equals(State.CLOSED) ? 1 : 0);
  }
  
  public void recordErrorRate(String serviceName, double errorRate) {
    meterRegistry.gauge("circuit_breaker_error_rate",
      Tags.of("service", serviceName),
      errorRate);
  }
}
```

Alerting:
```yaml
alerts:
  circuit_breaker_open:
    condition: circuit_breaker_state{state="OPEN"} > 0
    duration: 5m
    action: page_oncall
```

Dashboard (Grafana):
- Circuit breaker states (pie chart)
- Error rates over time (line graph)
- Service health status (table)

Benefit: visibility into fault tolerance, early warning.

Pitfall: alert fatigue (too many alerts); tune thresholds.

---

### Q498: What is sticky sessions vs stateless?

Sticky sessions: route requests to same server (maintain local state).

```
Client1 → Server A (session state stored in memory)
Client1 → Server A (same server, session accessible)
```

Stateless: no session state on server (store in external store).

```
Client1 → Server A (no session state)
Client1 → Server B (session fetched from Redis)
```

Sticky session implementation:
```yaml
spring:
  cloud:
    gateway:
      routes:
      - id: order-service
        uri: lb:order-service # load balancer with sticky sessions
        predicates:
        - Path=/api/orders/**
        filters:
        - StripPrefix=2
```

Stateless implementation:
```java
@RestController
public class OrderController {
  @PostMapping("/login")
  public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
    User user = userService.authenticate(request);
    String token = jwtProvider.generateToken(user);
    
    return ResponseEntity.ok(new AuthResponse(token));
  }
  
  @GetMapping("/orders")
  public ResponseEntity<List<Order>> listOrders(@RequestHeader("Authorization") String token) {
    User user = jwtProvider.validateToken(token);
    return ResponseEntity.ok(orderService.getOrders(user.getId()));
  }
}
```

Trade-off: sticky sessions (simple, local state), stateless (scalable, no affinity needed).

Pitfall: sticky sessions prevent load balancing; stateless requires distributed session store.

---

### Q499: What is request decompression and compression?

Compression: reduce response size (network bandwidth).

Gzip compression (HTTP negotiation):
```
Client: Accept-Encoding: gzip, deflate

Server:
  Content-Encoding: gzip
  {compressed response body}

Client decompresses automatically
```

Spring Boot configuration:
```yaml
server:
  compression:
    enabled: true
    min-response-size: 1024 # only compress > 1KB
    mimetypes:
    - application/json
    - application/xml
    - text/html
```

Custom compression:
```java
@RestController
public class OrderController {
  @GetMapping("/orders")
  public ResponseEntity<List<Order>> listOrders(
    @RequestHeader(value = "Accept-Encoding", required = false) String encoding) {
    
    List<Order> orders = orderService.getAllOrders();
    
    if (encoding != null && encoding.contains("gzip")) {
      byte[] compressed = compress(orders);
      return ResponseEntity.ok()
        .header("Content-Encoding", "gzip")
        .body(compressed);
    }
    
    return ResponseEntity.ok(orders);
  }
  
  private byte[] compress(Object obj) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
      gzip.write(objectMapper.writeValueAsBytes(obj));
    }
    return out.toByteArray();
  }
}
```

Benefit: reduce bandwidth (50-80% reduction), faster transfers.

Pitfall: compression overhead (CPU); only compress large responses.

---

### Q500: What is architectural evolution and scaling patterns?

System starts monolithic, evolves to distributed.

Phase 1: Monolith (single deployable unit)
```
Pros: simple deployment, easy debugging, transactional consistency
Cons: hard to scale, tight coupling, hard to change
```

Phase 2: Modular monolith (internal boundaries, separate deploy)
```
Pros: loose coupling within monolith, faster deployments
Cons: still single process, shared resources
```

Phase 3: Microservices (independent services)
```
Pros: independent scaling, independent deployments, team autonomy
Cons: operational complexity, distributed transaction challenges
```

Phase 4: Serverless/FaaS (function-as-a-service)
```
Pros: zero-management, pay-per-execution
Cons: vendor lock-in, cold starts, debugging complexity
```

Migration pattern:
```
1. Strangler pattern: gradually replace monolith functions
   - Old: OrderService (monolithic)
   - New: OrderServiceV2 (microservice)
   - Router: smart routing (% traffic to new service)

2. API gateway: serve as proxy during transition
   - Clients → API Gateway → monolith or microservices

3. Event streaming: trigger async workflows
   - Monolith publishes events
   - Microservices subscribe and replicate data
```

Example (order service migration):
```
Monolith: handles orders + payments + inventory

Step 1: Extract payment service
  - Monolith: publishes OrderCreatedEvent
  - PaymentService: subscribes, processes
  - Router: 1% traffic to new service

Step 2: Validate, then increase to 50%, then 100%

Step 3: Extract inventory service (repeat)

Final: 3 services (order, payment, inventory) replacing monolith
```

Benefit: continuous improvement, reduced risk (gradual migration).

Pitfall: architectural changes have operational cost; plan carefully.

---

### Q501: What's the difference between useMemo and useCallback?

`useMemo` memoizes a computed value; `useCallback` memoizes a function reference. Use `useMemo` when an expensive calculation should be skipped on re-renders; use `useCallback` to prevent child re-renders when passing functions as props.

---

### Q502: When should you use useLayoutEffect instead of useEffect?

Use `useLayoutEffect` for DOM reads/writes that must happen before the browser paints (synchronous). `useEffect` runs after paint and is preferred for side effects that don't block rendering.

---

### Q503: What is React Fiber?

Fiber is the reimplementation of React's reconciliation algorithm allowing incremental rendering and priorities. It enables interruptible work, better scheduling, and features like Suspense and concurrent rendering.

---

### Q504: How does React's reconciliation determine updates?

It compares element types; same type -> update props and reconcile children, different type -> unmount and mount. Keys are used to match elements in lists to avoid unnecessary reorders.

---

### Q505: What causes hydration mismatches and how to fix them?

Mismatch happens when server-rendered HTML doesn't match client render (random IDs, date/time, non-deterministic code). Fix by making render deterministic, delaying client-only code with checks, or using `useEffect` for client-only DOM changes.

---

### Q506: Explain React Suspense for data fetching.

Suspense lets components “suspend” rendering until async data is ready. Combined with a data-fetching library that throws promises, Suspense shows fallback UI while waiting and simplifies loading states.

---

### Q507: What are React Server Components (RSC)?

RSCs are components rendered on the server that can access server-only resources and stream HTML to clients, reducing client bundle size by keeping non-interactive logic server-side.

---

### Q508: How to avoid prop drilling in React?

Use Context API, state colocated higher, or patterns like composition, render props, or a state container (Redux/MobX) to avoid passing props deeply through many components.

---

### Q509: When to use Context vs Redux?

Context is for passing data without prop-drilling (theming, locale). Redux is better for complex global state with middleware, time-travel debugging, and predictable reducers.

---

### Q510: What are Error Boundaries?

Error boundaries are class components implementing `componentDidCatch` and `getDerivedStateFromError` to catch render-time errors of child components and show fallback UI; hooks cannot implement them directly.

---

### Q511: How does memoization with React.memo work?

`React.memo` wraps a component to skip re-render when props are shallowly equal. For complex props provide a custom comparison function.

---

### Q512: What's the difference between controlled and uncontrolled components?

Controlled components have value driven by React state (`value` + `onChange`). Uncontrolled components manage their own DOM state and are accessed via refs (`defaultValue`).

---

### Q513: How to optimize large lists in React?

Use windowing/virtualization (react-window/react-virtualized), stable keys, avoid inline functions, and memoize row components to minimize DOM and reconciliation costs.

---

### Q514: What are portals in React?

Portals render children into a DOM node outside the parent hierarchy, useful for modals, tooltips, and overlays while preserving React event bubbling.

---

### Q515: Explain React's synthetic event system.

React uses a cross-browser synthetic event wrapper for performance and consistency. Events are delegated at the root and pooled for reuse (pooling removed in newer React versions).

---

### Q516: How to handle forms efficiently in React?

Use controlled components for validation and immediate feedback; for complex forms consider libraries like Formik, React Hook Form for performance and easier validation.

---

### Q517: What is reconciliation of keyed lists?

Keys identify elements across renders; stable unique keys allow React to match, reuse, and reorder elements rather than re-create them—improving performance and preserving state.

---

### Q518: How to prevent unnecessary re-renders?

Memoize components (`React.memo`), functions (`useCallback`), values (`useMemo`), avoid creating new props inline, and lift state appropriately to reduce changing props.

---

### Q519: Explain render props pattern.

Render props pass a function as a prop to control what a component renders, enabling logic reuse. Example: `<DataLoader>{data => <UI data={data}/>}</DataLoader>`.

---

### Q520: What are Higher-Order Components (HOC)?

HOCs are functions that take a component and return an enhanced component, used to share cross-cutting concerns (e.g., withRouter, connect). Prefer hooks for new code.

---

### Q521: What is Strict Mode in React?

StrictMode activates additional checks and warnings (like identifying unsafe lifecycles). In development it may double-invoke certain functions to surface bugs, but has no effect in production.

---

### Q522: How does lazy loading work in React?

`React.lazy` + `Suspense` defers loading of component code until it's rendered, reducing initial bundle size. Use `import()` to split code at route or component boundaries.

---

### Q523: What's event pooling and is it still used?

Older React versions pooled SyntheticEvent objects for performance; modern React no longer pools events, and accessing event properties asynchronously may require copying values.

---

### Q524: How to test React components effectively?

Use React Testing Library for behavior-driven tests, Jest for unit tests and mocking. Prefer testing user interactions over implementation details.

---

### Q525: What is hydration and why is it important?

Hydration attaches React event handlers to server-rendered HTML on the client, enabling interactivity without re-rendering the whole UI. Proper hydration reduces time-to-interactive.

---

### Q526: How to measure React performance in production?

Use Web Vitals (LCP, FID/INP, CLS), profiling with React DevTools Profiler, telemetry, and real-user monitoring (RUM) to capture real-world metrics.

---

### Q527: What are common useEffect pitfalls?

Missing dependency arrays causing stale closures or infinite loops, running expensive sync work in effects, and failing to clean up subscriptions leading to memory leaks.

---

### Q528: Differences between useRef and useState?

`useRef` holds a mutable value that persists across renders without triggering re-renders; `useState` triggers re-renders when updated and is used for reactive UI updates.

---

### Q529: How to implement code splitting for routes?

Wrap route components with `React.lazy` and show fallbacks with `Suspense`. Tools like React Router support lazy-loaded route components to split bundles.

---

### Q530: What is tree shaking and how to enable it?

Tree shaking removes unused exports during bundling. Use ES modules (import/export) and bundlers like webpack/Rollup configured for production mode to enable tree shaking.

---

### Q531: How to optimize images in React apps?

Use responsive images (`srcset`), modern formats (WebP/AVIF), lazy loading, CDNs, and image optimization plugins or services (Imgix, Cloudinary) to reduce payloads.

---

### Q532: What is React Testing Library's guiding principle?

Test the app as users interact with it—query by text/role/label—avoid testing implementation details to keep tests resilient to refactors.

---

### Q533: How to handle accessibility in React?

Use semantic HTML, ARIA attributes when necessary, keyboard navigation, focus management, and tools like axe or Lighthouse to audit accessibility.

---

### Q534: Explain Concurrent Mode advantages.

Concurrent features (scheduling, interruptions) allow React to prepare multiple versions of UI and keep the app responsive by yielding work to the browser.

---

### Q535: What is the role of keys in reconciliation?

Keys give elements stable identity between renders. Avoid using index as key when order changes because it can break state preservation and lead to bugs.

---

### Q536: How to secure a React app against XSS?

Avoid `dangerouslySetInnerHTML`, sanitize external HTML, escape user input, use Content Security Policy (CSP), and keep dependencies up to date.

---

### Q537: Explain memoization pitfalls.

Overuse of memoization can add complexity and memory overhead; only memoize when renders are expensive or props change infrequently.

---

### Q538: How to handle internationalization (i18n)?

Use libraries like react-intl or i18next, extract strings, support pluralization and formatting, and lazy-load locale bundles for performance.

---

### Q539: What is server-side rendering benefit for SEO?

SSR renders full HTML for crawlers and social previews, improving SEO and perceived load time; combine with hydration for interactivity.

---

### Q540: How to implement optimistic UI updates?

Update UI immediately assuming success (optimistically), rollback on failure, and handle server confirmations—use unique temp IDs for pending items.

---

### Q541: What are React DevTools Profiler traces used for?

They show component render times, commit durations, and why components rendered (prop/state changes), helping identify bottlenecks.

---

### Q542: Explain SuspenseList briefly.

`SuspenseList` coordinates reveal order for multiple Suspense boundaries, allowing cascading or simultaneous reveal behaviors for better UX when loading multiple components.

---

### Q543: How to manage focus for accessibility in SPAs?

Move focus to meaningful elements on navigation, use `focus()` with refs, add skip links, and announce changes with ARIA live regions when appropriate.

---

### Q544: What is hydration mismatch debugging approach?

Compare server and client outputs, log rendered markup, remove non-deterministic code from render, and isolate components to find mismatch sources.

---

### Q545: How to reduce initial JS bundle size?

Code-split, remove polyfills you don't need, use lighter alternatives, tree-shake, lazy-load, and adopt modern bundlers like Vite for faster builds.

---

### Q546: What are React performance budgets?

Set targets (bundle size, TTI, LCP), track budgets in CI, and fail builds that exceed thresholds to keep app fast and predictable.

---

### Q547: How to test components with async effects?

Use `waitFor`/`findBy` utilities in React Testing Library to await UI changes, and mock network calls to control timing and outcomes.

---

### Q548: Explain useTransition hook.

`useTransition` marks updates as non-urgent, allowing React to keep UI responsive by showing intermediate states while transitioning to new content.

---

### Q549: What's the best way to handle authentication in React?

Keep tokens in memory or httpOnly cookies for security, avoid localStorage for sensitive tokens, and protect routes with client/server checks.

---

### Q550: How to plan for progressive enhancement in React?

Ensure basic functionality works without JS (server-rendered content), progressively add interactivity, and avoid blocking critical content on JS bundle loading.

---

### Q551: What is the virtual DOM and why does React use it?

The virtual DOM is an in-memory representation of the real DOM. React uses it to batch updates, calculate differences (diffs), and apply only necessary DOM changes, improving performance.

---

### Q552: How does React's useReducer hook work?

`useReducer` manages complex state by dispatching actions to a reducer function that returns new state. More scalable than `useState` for interdependent state values.

---

### Q553: What are the benefits of using TypeScript with React?

Type safety catches errors at compile time, improves IDE autocomplete, documents component APIs, and makes refactoring safer and more confident.

---

### Q554: How to optimize React app bundle size?

Use dynamic imports with lazy loading, remove unused dependencies, analyze bundles with tools like `webpack-bundle-analyzer`, and switch to lighter alternatives (preact, solid.js for some cases).

---

### Q555: What are controlled vs uncontrolled form inputs?

Controlled inputs have their value driven by state with onChange handlers (predictable). Uncontrolled inputs use refs to read values directly from the DOM when needed.

---

### Q556: How to handle global state with Context API efficiently?

Split contexts by concern, memoize provider value, use custom hooks to expose context, and consider splitting into multiple Contexts to avoid unnecessary re-renders.

---

### Q557: What is the difference between shallow and deep equality?

Shallow equality checks if object references are the same (===). Deep equality recursively compares all nested values. React uses shallow for props/state changes by default.

---

### Q558: How to implement authentication persistence in React?

Store auth tokens in httpOnly cookies (secure, no JS access) or memory, check hydration/app load for persisted session, and refresh tokens silently before expiry.

---

### Q559: Explain the concept of component composition.

Building UI by combining smaller reusable components rather than inheritance. Leads to flexible, maintainable code and better separation of concerns.

---

### Q560: What are React Hooks rules and why do they matter?

Hooks must be called at the top level (not in conditions/loops) and only from React function components. Ensures consistent hook order across renders for state access.

---

### Q561: How to test custom React Hooks?

Use `@testing-library/react-hooks` (or built-in renderHook in modern versions) to test hooks in isolation, mocking dependencies and asserting state/side effects.

---

### Q562: What is the difference between props and state?

Props are read-only input passed to components (immutable). State is mutable data owned by a component that triggers re-renders when updated.

---

### Q563: How to defer non-critical updates in React?

Use `useDeferredValue` or `useTransition` to mark updates as low-priority, allowing React to prioritize user input and keep UI responsive.

---

### Q564: Explain the concept of lifting state up.

Moving state from a child to a shared parent component to synchronize state across siblings. Enables data flow coordination without prop drilling if a single source of truth is needed.

---

### Q565: How to implement optimistic updates with error recovery?

Update UI immediately, store pending change, rollback on server error, and retry with user confirmation or automatic backoff.

---

### Q566: What is the render phase vs commit phase in React?

Render phase calculates changes (pure, can be paused), commit phase applies changes to DOM (side effects allowed). Effects run after commit.

---

### Q567: How to handle keyboard accessibility in React components?

Listen for keydown/keyup, support Tab for focus navigation, Escape to dismiss modals, Enter/Space for activations, and announce changes via ARIA live regions.

---

### Q568: What is the purpose of keys in React lists?

Keys give list items stable identity across renders, preventing state loss and incorrect reordering when list items are rearranged or filtered.

---

### Q569: How to implement dark mode toggle in React?

Store preference in state/context, apply CSS classes or theme variables on root element, persist to localStorage, and respect system preference via `prefers-color-scheme`.

---

### Q570: Explain the concept of controlled components in forms.

Form inputs controlled by React state; each input change updates state, and state value drives the input display. Enables validation, conditional rendering, and programmatic form control.

---

### Q571: What are the benefits of React Fragments?

Allow grouping multiple elements without a wrapper div, reducing DOM clutter, improving performance (fewer nodes), and avoiding layout issues from extra divs.

---

### Q572: How to implement infinite scroll in React?

Use Intersection Observer API to detect scroll near bottom, fetch next page on trigger, append items to list, and show loading indicator between fetches.

---

### Q573: What is the impact of key={index} in lists?

Using index as key breaks component state when list reorders. Items may display wrong state. Use unique, stable identifiers (IDs) from data instead.

---

### Q574: How to implement search with debounce in React?

Debounce onChange handler using `useRef` and `setTimeout`, cancel previous timer on new input, and fetch results only after user stops typing (improves performance).

---

### Q575: What are React's built-in performance profiling tools?

React DevTools Profiler tab shows render times and why components re-rendered. Use it to identify bottlenecks before optimizing.

---

### Q576: How to implement form validation with React Hook Form?

Use register to bind inputs, define validation rules, and display errors. Handles uncontrolled inputs efficiently with minimal re-renders.

---

### Q577: Explain the purpose of dangerouslySetInnerHTML.

Allows setting raw HTML strings in React (bypassing escaping). Use only for trusted content (Markdown, rich text editors); avoid user-generated content to prevent XSS.

---

### Q578: How to handle file uploads in React?

Use file input with change handler, read file with FileReader API or fetch with FormData, and upload via fetch/axios with progress tracking.

---

### Q579: What is React's StrictMode warning about double state updates?

In development, React intentionally double-invokes effects and render functions to surface side effects. Production is not affected; fix by ensuring pure effects.

---

### Q580: How to implement custom hooks for reusable logic?

Extract stateful logic into a function starting with "use", call other hooks, and return state/functions. Custom hooks enable logic sharing without render props or HOCs.

---

### Q581: What are the performance implications of useEffect dependencies?

Empty deps = runs once; missing deps = runs every render; correct deps = runs when dependencies change. Wrong deps cause stale closures or unnecessary re-runs.

---

### Q582: How to implement pagination in React?

Maintain page state, calculate offset/limit, fetch page on state change, disable prev/next buttons at boundaries, and preserve scroll position or focus.

---

### Q583: Explain the virtual DOM diffing algorithm.

React compares old and new virtual trees, identifying changed elements, then applies minimal DOM updates. Keys help match elements and preserve state during reorders.

---

### Q584: How to implement tooltips in React?

Use portals to render outside hierarchy, position with CSS or libraries (Popper.js), show on hover/focus, hide on blur/escape, and only render when visible.

---

### Q585: What is the role of the ref in React?

Refs provide direct access to DOM elements or class instance values, bypassing React's declarative flow. Use sparingly for focus, text selection, media playback, or integrations.

---

### Q586: How to prevent memory leaks in React?

Unsubscribe from listeners, cancel async requests, and clear timers in useEffect cleanup functions. Especially important for long-lived components.

---

### Q587: Explain the concept of prop drilling and solutions.

Props passed through many intermediate components to reach a distant child. Solve with Context API, render props, custom hooks, or state containers (Redux).

---

### Q588: How to implement search autocomplete in React?

Debounce user input, fetch suggestions, cache results, display dropdown, handle keyboard navigation, and close on selection or blur.

---

### Q589: What is the difference between controlled and uncontrolled refs?

Controlled refs update via callback on every render; uncontrolled refs hold a persistent reference. Uncontrolled is simpler but less flexible.

---

### Q590: How to implement breadcrumb navigation in React?

Track current location from URL or router, build path list, render links for each ancestor level, mark current page as inactive, and handle click navigation.

---

### Q591: What are the benefits of using custom hooks over render props?

Custom hooks are simpler to read and compose, avoid the "wrapper hell" of nested render props, and integrate naturally with other hooks.

---

### Q592: How to implement modal dialogs in React?

Create modal component with portal, control visibility with state, disable body scroll, add backdrop, focus manager, and close on escape/backdrop click.

---

### Q593: Explain React's concurrent features briefly.

Concurrent rendering allows React to pause and resume work between renders, prioritize high-urgency updates, and keep the app responsive even during heavy computations.

---

### Q594: How to handle date and time in React?

Use libraries like Day.js or date-fns (lighter than Moment.js), store dates as UTC ISO strings, format for display only, and validate user input.

---

### Q595: What is the impact of inline functions as props?

Inline functions create new references on every render, breaking React.memo and causing unnecessary child re-renders. Use useCallback to memoize function references.

---

### Q596: How to implement a notification/toast system in React?

Use context or a custom hook to manage toast state, render toasts in a portal, auto-dismiss with setTimeout, allow manual dismiss, and queue multiple toasts.

---

### Q597: Explain the concept of pure functions in React.

Pure functions return the same output for the same input, with no side effects. Components should be pure to ensure consistent rendering and enable optimizations.

---

### Q598: How to implement client-side filtering and sorting?

Store filters/sort state, apply to data array using Array methods, memoize results to avoid recalculation, and validate filter/sort parameters.

---

### Q599: What are React's limitations and when to use alternatives?

React excels at interactive UIs; for static content, consider other tools. Limitations: learning curve, complexity for simple apps, and bundle size. Alternatives: Svelte, Vue, Solid.js.

---

### Q600: How to plan a React project structure for scalability?

Organize by feature (pages, components, hooks, utils per feature), separate concerns (styling, testing), use a clear naming convention, and establish architectural boundaries early.

---

### Q601: What's the relationship between React state and ReactDOM rendering?

React state lives in component memory; ReactDOM renders that state to the DOM. State change triggers re-render via ReactDOM.render/createRoot.

---

### Q602: How to optimize repeated API calls in React?

Cache responses in state or Context, dedupe requests with request coalescing, use SWR or React Query for automatic stale-while-revalidate, and implement request timeouts.

---

### Q603: What are React's key limitations for real-time apps?

React updates are batched and asynchronous; WebSockets/Server-Sent Events need separate handling. Use libraries like Socket.io or consider real-time frameworks (Meteor) for active sync needs.

---

### Q604: How to handle complex nested state updates efficiently?

Use Immer library to write mutations naturally (immutably applied), adopt useReducer for structured state machines, or flatten state shape to minimize deep nesting.

---

### Q605: What is the purpose of React's `key` prop in reconciliation?

`key` gives elements stable identity across renders, allowing React to preserve component state and DOM position when the list reorders, avoiding bugs and unnecessary re-renders.

---

### Q606: How to implement a real-time collaborative editing UI?

Use operational transformation or conflict-free replicated data types (CRDTs), sync changes via WebSocket, show presence cursors, and handle concurrent edits gracefully.

---

### Q607: What are React's best practices for large-scale state management?

Use Redux/MobX for predictable updates, normalize state shape (flat, non-nested), split stores by domain, leverage middleware for side effects, and use selectors for derived state.

---

### Q608: How to debug React performance issues in production?

Use Web Vitals monitoring (CLS, LCP, FID), capture session replays with tools like Sentry, analyze bundle size with bundlesize or webpack-bundle-analyzer, and use profiling in DevTools.

---

### Q609: What is the difference between React.memo and useMemo?

`React.memo` prevents component re-render if props are shallowly equal; `useMemo` memoizes a computed value inside a component. Use memo for component optimization, useMemo for expensive calculations.

---

### Q610: How to implement drag-and-drop with React?

Use react-beautiful-dnd or react-dnd libraries for high-level APIs, or implement with onMouseDown/onMouseMove/onMouseUp for custom behavior; maintain dragged item state and update order on drop.

---

### Q611: What is React's approach to error boundaries vs error handling?

Error boundaries catch render-time errors and prevent full app crash. For runtime/async errors, use try/catch, error state, fallback UI, or libraries like react-error-boundary.

---

### Q612: How to implement form state synchronization across tabs?

Use localStorage or sessionStorage to sync form state, listen to `storage` events for changes, or use Portals with a shared context for cross-tab communication.

---

### Q613: What are the tradeoffs of useCallback vs inline functions?

`useCallback` memoizes function reference (better for props) but adds memory overhead; inline functions are simpler but break React.memo. Use callback when passing to optimized children.

---

### Q614: How to optimize CSS-in-JS performance in React?

Use styled-components with babel plugin, avoid creating styles inside render, leverage automatic critical CSS extraction, and consider Tailwind CSS for smaller bundles and better performance.

---

### Q615: What is React Query (TanStack Query) advantage?

React Query manages server state automatically: caching, synchronization, background refetching, stale-while-revalidate, retry logic, and deduplication without Redux boilerplate.

---

### Q616: How to implement PWA features in a React app?

Register service worker (offline support), add Web App Manifest (installable), implement cache strategies (Cache-first, Network-first), and handle push notifications.

---

### Q617: What's the impact of preloading and prefetching in React apps?

Preload critical resources (JS, fonts), prefetch likely next routes, use `<link rel="preconnect">` for DNS. Improves perceived performance and Time-to-Interactive.

---

### Q618: How to prevent XSS attacks in React?

Escape user input (React does by default), avoid `dangerouslySetInnerHTML`, use libraries like DOMPurify for user-generated HTML, and implement Content Security Policy headers.

---

### Q619: What is the relationship between React render cycles and browser repaints?

React renders to virtual DOM (fast), then reconciles, applying minimal DOM changes. Browser paints only changed elements. Fewer DOM mutations = fewer repaints.

---

### Q620: How to handle long-running operations in React without blocking UI?

Use Web Workers for CPU-intensive tasks, split work into chunks with setTimeout, or use requestIdleCallback to defer non-critical work until browser is idle.

---

### Q621: What are React Suspense limitations for data fetching?

Suspense requires libraries that throw promises, doesn't handle retries/errors natively, and can cause "waterfall" requests if nested. Use React Query or server-side fetching for better control.

---

### Q622: How to implement a stable focus management system in React?

Store focused element ref/ID in state, restore focus after modal closes, use ARIA `aria-live` for announcements, and skip links for keyboard navigation in SPAs.

---

### Q623: What is the cost of context re-renders when deeply nested?

Context value changes cause all consumers to re-render regardless of actual value change. Mitigate by splitting contexts by concern or memoizing child components.

---

### Q624: How to optimize images in React without external serverless?

Use responsive srcset, lazy-load with Intersection Observer, convert to WebP/AVIF, compress on build with imagemin-webpack-plugin, and implement native lazy loading.

---

### Q625: What is the advantage of Next.js over plain React?

Next.js provides: server-side rendering, static generation, built-in routing, API routes, image optimization, automatic code-splitting—reducing boilerplate and improving SEO/performance.

---

### Q626: How to handle authentication state across page reloads in React?

Check token from httpOnly cookie or local storage on app mount, restore session, and validate token with server. Use context or Redux to maintain authentication state.

---

### Q627: What are React's constraints for animations?

React batches updates; use CSS animations for smoothness, requestAnimationFrame for precise timing, or libraries like Framer Motion for complex orchestration without blocking JS.

---

### Q628: How to structure tests for complex React components?

Test behavior (user interactions) over implementation; use React Testing Library, mock external dependencies, test edge cases and error states, and maintain fast test suites.

---

### Q629: What is automatic batching in React 18?

React 18 batches state updates automatically (even async), reducing re-renders. Disable with `flushSync` if immediate DOM update needed (rare).

---

### Q630: How to implement a multi-language support system efficiently?

Use context or library (react-intl, i18next), load locale on app mount, cache translations, support pluralization and formatting, and avoid translating every string inline.

---

### Q631: What's the role of `trackingState` in React debugging?

Tracking state changes helps identify unexpected mutations or stale state. Use React DevTools, Redux DevTools, or logging to monitor state flow throughout component lifecycle.

---

### Q632: How to implement a responsive layout without media queries?

Use CSS Grid with auto-fit/minmax, Flexbox with flexible sizing, CSS Container Queries for responsive component logic, or Tailwind's responsive prefixes (sm:, md:, lg:).

---

### Q633: What is the overhead of component composition in React?

Each component adds a small overhead (wrapper divs in portal, context consumers). Optimize by avoiding unnecessary wrapper components or using React.Fragment to eliminate divs.

---

### Q634: How to test async React components effectively?

Use `waitFor` to await state updates, mock fetch with proper promises, test loading/error/success states separately, and avoid async/await in test setup (use beforeEach).

---

### Q635: What's the advantage of Static Generation over SSR in Next.js?

Static generation is faster (precomputed HTML), cacheable on CDN, and reduces server load. Downside: can't personalize per-user without client-side hydration. Use ISR (Incremental Static Regeneration) for stale data.

---

### Q636: How to implement a notification system that persists across navigation?

Use a top-level context for notifications, render Portal outside React tree, manage queue with IDs, auto-dismiss with timers, and allow manual dismiss.

---

### Q637: What is the React mental model for async operations?

Treat async results as state updates. On mount, async operation starts. Result updates state → re-render. Cleanup on unmount. Think in terms of side effects, not imperative callbacks.

---

### Q638: How to optimize Redux selector performance?

Use `reselect` to memoize selectors, avoid creating new arrays/objects in selectors, split selectors by concern, and normalize state to avoid deep cloning.

---

### Q639: What's the role of `Object.freeze` in React state?

Freezing state prevents accidental mutations in development. Doesn't prevent state re-renders; use only for debugging. Immer library is better for enforcing immutability.

---

### Q640: How to implement a resilient offline-first React app?

Use service workers for caching, sync pending changes when online (Background Sync API), show conflict resolution UI, and persist app state to IndexedDB.

---

### Q641: What are React's accessibility gotchas?

Focus management in SPAs, announcement of dynamic content via aria-live, proper heading hierarchy, color contrast, keyboard navigation, and testing with screen readers.

---

### Q642: How to handle payment flows in React securely?

Never store sensitive card data client-side; use Stripe Elements or similar to tokenize, send token to server, verify server-side. Implement PCI compliance (use hosted forms).

---

### Q643: What's the impact of CSS-in-JS on React performance?

CSS-in-JS adds runtime overhead (parsing, injection). Mitigate with babel plugins for compile-time CSS extraction, and consider Tailwind or CSS Modules for static styles.

---

### Q644: How to implement feature detection and graceful degradation in React?

Check API availability (navigator.geolocation, localStorage), provide fallback UI, progressive enhancement (basic works without JS), and inform users of limited functionality.

---

### Q645: What is React's approach to immutability without Immer?

Spread operators (`...obj`, `[...arr]`), Array methods (map, filter, concat), and Object.assign. Verbose for deep updates; Immer reduces boilerplate significantly.

---

### Q646: How to optimize React for low-end devices?

Bundle size: tree-shake, lazy-load, split code. Runtime: use useMemo sparingly, avoid large list renders (virtualize), reduce JS execution, defer non-critical work.

---

### Q647: What is the relationship between React keys and component identity?

Keys tell React which elements are the same across renders. Stable keys preserve component state and DOM position. Index keys break if list reorders.

---

### Q648: How to handle timezone-aware scheduling in React?

Store times as UTC, display in user's timezone, handle daylight saving changes, and use libraries like date-fns with timezone support for reliable conversions.

---

### Q649: What's the cost of unnecessary prop passing in React?

Each prop passed increases component re-check cost (shallow comparison). Minimize props via composition, extract child components, use context for distant data, or split into smaller components.

---

### Q650: How to validate API responses in React before rendering?

Parse response with Zod/io-ts schema validation, catch type mismatches early, show error state if response invalid, and log violations for debugging API contract issues.

---

### Q651: What's the relationship between React event handlers and event bubbling?

React uses synthetic events which bubble by default. Stop propagation with `e.stopPropagation()`. Understand that event delegation is handled at root level by React.

---

### Q652: How to implement a data-driven table component efficiently?

Virtualize with react-window for large datasets, memoize rows, use stable cell renderers, implement sorting/filtering on backend for scalability, and lazy-load pagination.

---

### Q653: What are React's constraints for building real-time dashboards?

Frequent updates can cause re-render thrashing. Use debounce/throttle for data updates, batch updates with Fiber scheduler, leverage Web Workers for heavy computations, and implement viewport-based rendering.

---

### Q654: How to handle dependent form field validations in React?

Track field dependencies in state, trigger re-validation when dependent field changes, provide feedback linking fields, and use react-hook-form watch for reactive validation.

---

### Q655: What is the purpose of React's `defaultValue` vs `value`?

`defaultValue` sets initial value for uncontrolled input; `value` drives controlled input. Mix them to transition from uncontrolled to controlled (anti-pattern in production).

---

### Q656: How to implement authentication refresh token flow in React?

Store refresh token httpOnly cookie, use interceptor to auto-refresh on 401, retry original request, and implement token rotation for enhanced security.

---

### Q657: What are React's limitations for building AR/VR experiences?

React isn't optimized for 3D rendering. Use Three.js with react-three-fiber for WebGL, but React's re-render overhead isn't ideal for high-fps 3D. Consider vanilla JS for graphics-heavy features.

---

### Q658: How to optimize bundle size when using multiple large libraries?

Tree-shake unused exports, dynamically import heavy libraries (code-split), use lighter alternatives (preact, date-fns vs moment), remove polyfills for modern browsers, and analyze with bundle analyzer.

---

### Q659: What's the role of Composition API vs Options API thinking in React?

React uses Composition (hooks compose logic). Think in terms of composing small functions not opposed to Options (Vue). Hooks force functional thinking but are more flexible.

---

### Q660: How to implement graceful cache invalidation in React Query?

Use `queryClient.invalidateQueries()` to mark queries stale, `refetchOnMount`/`refetchOnReconnect` for fresh data, and strategic cache time (staleTime) to balance freshness vs redundant fetches.

---

### Q661: What is the cost of Context API at scale?

Context re-renders all consumers when value changes. At scale (100+ deeply nested components), consider splitting contexts by concern or adopting Redux to mitigate unnecessary re-renders.

---

### Q662: How to handle race conditions in async React components?

Ignore stale responses by tracking request ID, abort stale fetch requests with AbortController, or use React Query which handles race condition internally.

---

### Q663: What's the advantage of Storybook for React component development?

Storybook provides isolated component development, interactive testing without app context, visual regression testing, and auto-documentation from stories.

---

### Q664: How to implement animated page transitions in React Router?

Use Framer Motion with location state, coordinate animation timing with route changes, show loading state during navigation, and handle stale animations on unmount.

---

### Q665: What are React's best practices for handling files larger than Closure?

Upload with resumable chunks (tus.io), show progress, retry failed chunks, validate hash on server, and clean up incomplete uploads server-side after timeout.

---

### Q666: How to implement a self-healing React component?

Detect error state, retry logic with exponential backoff, reset state on recovery, and show user feedback about recovery attempt and result.

---

### Q667: What is the role of Webpack HMR in React development?

Hot Module Replacement preserves component state during file changes, enabling fast iteration. Use react-refresh for modern HMR. Disable HMR in production.

---

### Q668: How to handle dynamic CSS variables with React state?

Store color/size values in state, update CSS custom properties via `style.setProperty()` on root element, enable theme switching without full reload.

---

### Q669: What's the advantage of static site generation (SSG) in Next.js?

SSG pre-renders pages at build time (fast, cacheable, CDN-friendly). Best for static content. ISR allows periodic re-generation without full rebuild.

---

### Q670: How to implement safe global state updates in React?

Use Redux with reducers (pure functions), Redux Middleware for async, or Context with useReducer for small apps. Immutable updates prevent silent bugs.

---

### Q671: What are React's constraints for building collaborative UIs?

Handle concurrent user edits (CRDTs), sync deltas efficiently (WebSocket), merge changes (operational transformation), show presence awareness, and gracefully handle connection loss.

---

### Q672: How to measure React app performance like a user perceives it?

Track Core Web Vitals (LCP, FID/INP, CLS), use RUM (real user monitoring), monitor per route, and correlate with error rates and user feedback.

---

### Q673: What is the purpose of React's `key` in animation?

Changing `key` forces React to unmount/remount component, retriggering mount animations. Use to trigger animation for same-type elements at different positions.

---

### Q674: How to implement a type-safe Redux-like hook for state management?

Use useReducer with TypeScript for action types, provide dispatch function with type-safe action creators, or adopt Zustand/Jotai for simpler typed stores.

---

### Q675: What's the role of Web Components in React?

React can wrap Web Components (custom elements), but integration is limited because React doesn't manage Web Component internals. React 19 improves interop with ref callbacks.

---

### Q676: How to optimize accessibility testing for React components?

Use axe-core for automated checks, test keyboard navigation, verify focus management, use screen reader (NVDA, JAWS), and adopt WCAG 2.1 AA standards.

---

### Q677: What are React's best practices for handling large JSON payloads?

Stream large responses (chunked transfer encoding), parse incrementally with streaming JSON parser, compress with gzip, and load data on demand (pagination).

---

### Q678: How to implement a resilient image loading strategy in React?

Preload critical images, lazy-load below fold, show placeholder while loading, provide fallback on error, retry failed loads, and optimize with CDN.

---

### Q679: What is the cost of re-exporting in React modules?

Re-exporting increases bundle size if not tree-shaken. Use ES6 named exports, avoid wildcard imports in bundler, and leverage bundler magic comments for optimization.

---

### Q680: How to handle timezone display consistency in React apps?

Store all times as UTC ISO strings, display in user's timezone, use date-fns/Day.js with timezone plugin, and handle DST transitions gracefully.

---

### Q681: What's the advantage of snapshot testing in Jest?

Snapshot testing captures component output, alerts on unexpected changes. Downside: false positives, requires manual review. Use sparingly for stable UIs, not for logic testing.

---

### Q682: How to implement a safe unsubscribe pattern in React effects?

Return cleanup function from useEffect that unsubscribes. For Observables, call `.unsubscribe()`. For event listeners, call `.removeEventListener()`. Prevent memory leaks.

---

### Q683: What are React's constraints for building multiplayer games?

React lacks low-latency update loop (render cycles too slow). Use game engines (Phaser, Babylon.js) or vanilla Canvas/WebGL. React can manage UI overlay only.

---

### Q684: How to optimize SVG rendering in React?

Minimize SVG complexity, memoize `<svg>` component, use CSS transforms if animating, avoid rendering large SVGs in lists, and consider CSS or Canvas for very complex graphics.

---

### Q685: What is the role of `useImperativeHandle` hook?

Expose imperative methods from child component to parent via ref. Use sparingly (most cases better solved with props). Example: focus DOM element or play animation from parent.

---

### Q686: How to implement state persistence with encryption in React?

Encrypt sensitive state before storing in localStorage, decrypt on load, use libsodium or TweetNaCl.js for encryption, and handle key management securely.

---

### Q687: What's the relationship between React render count and performance?

More renders = more CPU. Identify slow renders with Profiler (look for rerenders without prop changes), memoize expensive components, and optimize dependency arrays.

---

### Q688: How to handle version conflicts in React dependencies?

Use npm shrinkwrap or lock file to pin versions, use peer dependencies carefully, test major version upgrades in separate branch, and use automated dependency updates (dependabot).

---

### Q689: What are React's best practices for handling deep links in SPAs?

Preserve app state in URL (query params, path), restore state on navigation, use URL as single source of truth, and test deep link flows thoroughly.

---

### Q690: How to implement a resilient polling mechanism in React?

Poll with exponential backoff on error, stop polling when connection lost, detect stale data with timestamps, and use WebSocket as fallback for real-time updates.

---

### Q691: What is the cost of useCallback in tight loops?

`useCallback` adds memory overhead for each instance. Avoid in loops; move callbacks outside or use refs. For list items, memoize at item level, not inside loop.

---

### Q692: How to handle cross-origin requests safely in React?

Use CORS headers on server, validate origin, avoid storing sensitive data in responses, implement CSRF tokens, and use httpOnly cookies for auth tokens.

---

### Q693: What's the advantage of TypeScript for React component APIs?

Type interfaces auto-document props, catch errors at compile time, enable IDE autocomplete, and simplify refactoring with type safety across call sites.

---

### Q694: How to implement efficient search indexing in React?

Index on backend (Elasticsearch, Meilisearch), send queries to server, cache results, show real-time suggestions as user types, and lazy-load results on scroll.

---

### Q695: What are React's constraints for building low-bandwidth apps?

Minimize JS bundle, use web workers for processing, implement aggressive caching, send minimal JSON (no extra fields), and use service workers for offline fallback.

---

### Q696: How to implement a self-updating state in React without external polling?

Use Server-Sent Events (SSE) for server pushes, WebSocket for bidirectional updates, or implement background sync (background-sync API) for reliable offline-first updates.

---

### Q697: What is the role of memo composition in React?

Component composition with memo prevents re-renders of unchanged subtrees. Compose to isolate state changes, avoiding unnecessary memoization of larger trees.

---

### Q698: How to validate form state machine transitions in React?

Define valid transitions as object map, validate before dispatching action, show error if transition invalid, and test all valid/invalid paths.

---

### Q699: What's the advantage of IndexedDB over localStorage for React apps?

IndexedDB supports larger storage (unlimited vs 5-10MB), queries, indexes, and transactions. Use for app data, localStorage for simple key-value config.

---

### Q700: How to plan React app architecture for team scalability?

Establish clear folder structure (feature-based), enforce code review standards, use shared component libraries, document patterns, enforce TypeScript, and automate testing/linting.

---

### Q701: What is the relationship between React reconciliation and object identity?

React uses Object.is() for comparing objects. New object instances (even with same values) are considered different, triggering re-renders. Memoize objects/functions for stable references.

---

### Q702: How to implement a field-level permission system in React?

Store user permissions in context, check permission before rendering field, disable/hide sensitive inputs, and validate on server (never trust client-side checks alone).

---

### Q703: What's the role of React.lazy in code splitting?

React.lazy defers chunk loading until component renders. Reduces initial bundle, reveals chunks on demand. Pair with Suspense for loading state and error boundary for errors.

---

### Q704: How to handle concurrent requests with rate limiting in React?

Use a request queue with worker pool, implement exponential backoff on 429, show user feedback about rate limit, and cache responses to minimize requests.

---

### Q705: What are React's best practices for handling date ranges?

Use ISO format (YYYY-MM-DD), validate range (start <= end), localize display, handle edge cases (inclusive/exclusive), use date library (date-fns, Day.js) for operations.

---

### Q706: How to implement a component with prop-drilling avoidance via composition?

Pass children as props (composition), use render props for configuration, or Context for deeply nested sharing. Choose based on reusability needs.

---

### Q707: What is the cost of function composition in React?

Each higher-order function adds a wrapper component and memory overhead. Balance readability with performance; avoid excessive composition chains.

---

### Q708: How to optimize React app for Core Web Vitals (LCP, FID/INP, CLS)?

LCP: preload critical resources, optimize images. FID/INP: reduce JS execution blocking the main thread. CLS: avoid content shifts, reserve space for dynamic content.

---

### Q709: What's the advantage of declarative state management over imperative?

Declarative (describe desired state) is easier to reason about, test, and debug. React encourages declarative; use imperative sparingly for side effects.

---

### Q710: How to implement a fair priority queue for React renders?

Use Fiber scheduler (React handles internally), or implement custom with task IDs and priorities. High-priority tasks (user input) skip ahead of low-priority (analytics).

---

### Q711: What are React's constraints for building progressive disclosure UIs?

State explosion (many visibility flags). Solution: group related items in containers or use indexes to track expanded states. Memoize to prevent unnecessary renders.

---

### Q712: How to handle concurrent mutations in offline-first React apps?

Track changes per entity, use vector clocks for causality, implement CRDTs for automatic merging, or implement manual conflict resolution UI.

---

### Q713: What is the role of `React.StrictMode` in development?

StrictMode intentionally double-calls render/effects in dev to surface side effects. Helps find pure function violations. No impact in production.

---

### Q714: How to implement efficient filtering across large datasets in React?

Filter on backend with query params, paginate results, memoize filter state, debounce input changes, and lazy-load filtered results on scroll.

---

### Q715: What's the advantage of zero-JS delivery for critical content in React?

Render critical content server-side (Next.js SSR), skip JS for initial paint, hydrate interactivity separately. Improves First Contentful Paint.

---

### Q716: How to handle modal nesting in React?

Maintain stack of modals, close from top, focus previous modal on close, manage z-index automatically, and prevent body scroll for all open modals.

---

### Q717: What are React's best practices for form auto-save?

Save on field blur with debounce, optimistically update, show save status, handle conflicts, and clear pending changes after server ack.

---

### Q718: How to implement a resilient retry strategy for failed uploads?

Chunk uploads, retry individual chunks on failure, validate chunk hash, resume from last successful chunk, and timeout after max retries.

---

### Q719: What is the cost of inline object literals in React?

Every render creates new object (even if values same), breaking React.memo and useCallback. Move literals outside component or memoize with useMemo.

---

### Q720: How to optimize React app for search engine crawling?

Use Server-Side Rendering (SSR), create sitemaps, add meta tags dynamically, implement Open Graph tags, and use Next.js for built-in SEO support.

---

### Q721: What's the role of React DevTools Profiler for optimization?

Profiler shows render duration per component, re-render reasons, and render counts. Identify slow components and unnecessary re-renders for targeted optimization.

---

### Q722: How to implement a stateless authentication system in React?

Use JWTs (stateless tokens) with expiry, refresh token rotation, store token in httpOnly cookie, and validate on server. Avoids session server-side state.

---

### Q723: What are React's constraints for handling subtitles/captions?

Sync timing with video playback, handle different formats (VTT, SRT), position on screen, support multiple languages, and test with screen readers for accessibility.

---

### Q724: How to implement efficient text search highlighting in React?

Split text by search term, wrap matches with highlight span, memoize search results, debounce search input, and handle special regex characters safely with escaping.

---

### Q725: What is the purpose of React's `displayName` for debugging?

`displayName` labels components in DevTools and error messages. Custom displayName clarifies purpose, especially for HOCs and functional components without obvious names.

---

### Q726: How to handle internationalized URLs in React Router?

Prefix routes with locale (/:lang/), validate locale on app load, provide locale switcher, redirect missing locale to default, preserve path on locale change.

---

### Q727: What's the advantage of viewport-relative sizing in React layouts?

Use vw/vh/cqw units for responsive sizing, avoid pixel-dependent layouts, use CSS Grid with fr units, leverage CSS Subgrid for consistent layouts.

---

### Q728: How to implement a circular dependency-free component structure?

Avoid child → parent imports, use Context to pass data down, abstract shared utilities to separate module, and use dependency injection for cross-cutting concerns.

---

### Q729: What are React's best practices for handling clipboard operations?

Use modern Clipboard API, request permission, provide user confirmation for sensitive pastes, clear clipboard after sensitive data removal, and handle paste image data.

---

### Q730: How to optimize animation performance in React?

Use CSS transforms/opacity (GPU-accelerated), avoid animating expensive properties (width, height), use requestAnimationFrame for custom animations, and debounce scroll animations.

---

### Q731: What is the cost of conditional imports in React?

Dynamic imports (import()) defer loading but add runtime overhead. Use for uncommon features; avoid for common ones. Tree-shaking works best with static imports.

---

### Q732: How to implement a fault-tolerant GraphQL client in React?

Implement retry logic, batch queries for efficiency, cache results, handle partial errors, and fallback to stale cache on failure.

---

### Q733: What's the role of React Profiler API programmatically?

Use Profiler component to measure subtree render times, log metrics, and trigger actions based on performance thresholds (e.g., alert slow renders).

---

### Q734: How to handle user interactions before hydration in React apps?

Queue events during hydration, replay after hydration complete, or disable interactions until hydration done. Next.js handles this automatically with suppressHydrationWarning.

---

### Q735: What are React's constraints for building data visualization dashboards?

Large datasets cause re-render thrashing. Use Canvas/SVG rendering libraries (Recharts, D3 with React), virtualize large charts, and defer non-visible updates.

---

### Q736: How to implement a debounced search with React Query?

Use `queryKey` with search term, debounce term change, React Query deduplicates requests, and caches previous searches for instant recall.

---

### Q737: What is the relationship between React hooks and closure?

Hooks rely on closures to access component state. Dependency array prevents stale closures by re-creating function when dependencies change.

---

### Q738: How to validate complex interdependent form fields in React?

Maintain validation schema with rules and dependencies, validate on blur and submit, show field-and-dependency-specific errors, use yup/zod for declarative validation.

---

### Q739: What's the advantage of SWR (Stale-While-Revalidate) pattern for React?

SWR serves cached data immediately, revalidates in background, merges new data without flicker. Improves perceived performance and UX for data fetching.

---

### Q740: How to implement a component library with CSS isolation?

Use CSS Modules, Shadow DOM, or CSS-in-JS libraries. Provide clear variants (props), document with Storybook, version separately, and publish to npm.

---

### Q741: What are React's best practices for handling error messages?

Be user-friendly (no stack traces), suggest resolution, log full errors server-side, implement error logging service, and categorize errors (4xx, 5xx) for appropriate messaging.

---

### Q742: How to optimize React app for slow network conditions?

Minify, compress, code-split, lazy-load images, use Service Workers for offline fallback, and test with throttled network (Chrome DevTools).

---

### Q743: What is the cost of `console.log` in React production?

Logs reduce performance if high volume. Use environment checks (if (import.meta.env.DEV)) to remove logs in production, or use debug library for conditional logging.

---

### Q744: How to implement a resilient subscription-based UI in React?

Subscribe in useEffect, unsubscribe in cleanup, handle subscription errors, use React Query or SWR for automatic management, and implement exponential backoff on connection loss.

---

### Q745: What's the role of React Suspense List for UX?

SuspenseList coordinates reveal order of multiple Suspense boundaries. Revealorder prop (together, forwards, backwards) controls loading sequence for better UX.

---

### Q746: How to handle form recovery after page reload in React?

Auto-save form state to localStorage, restore on mount, show unsaved changes warning, and clear after server confirms save.

---

### Q747: What are React's constraints for building high-frequency trading UIs?

React's re-render latency inadequate for subsecond updates. Use WebSockets for real-time data, Web Workers for heavy computation, and separate graphics rendering from React.

---

### Q748: How to implement a unified error tracking system in React?

Use error boundary with Sentry integration, track errors with custom metadata, deduplicate similar errors, and create dashboards for error trends.

---

### Q749: What is the purpose of React's `key` in fragments?

React.Fragment doesn't support `key` prop (only in lists via map). Use `<>...</>` shorthand; if you need keys, use `<React.Fragment key={id}>`.

---

### Q750: How to plan React component dependency graph for modularity?

Map component dependencies, minimize circular refs, group related components, use Context for cross-cutting concerns, and publish shared components separately.

---

### Q751: What's the relationship between React render props and function-as-child pattern?

Both pass render logic via props (function-as-child is a type of render prop). Functional approach, preferred over HOCs. Enable complex data flow without nested components.

---

### Q752: How to implement field masking for inputs in React?

Use libraries (react-input-mask, cleave.js) or implement custom with onChange handler tracking, validate user input against mask pattern, and preserve cursor position.

---

### Q753: What are React's constraints for building accessibility-first designs?

Plan for keyboard navigation, screen readers, contrast, focus management upfront. Testing requires actual screen readers (not just automated tools) for comprehensive coverage.

---

### Q754: How to handle state reset across different React views?

Track view/route in state, provide reset button with context, or integrate with router to reset on navigation. Use custom hook for reusable reset logic.

---

### Q755: What is the cost of large switch statements in React render?

Switch statements for rendering are readable but not optimized. Extract to render functions or separate components for large switches. No significant perf difference if well-structured.

---

### Q756: How to implement a real-time notification badge system in React?

Maintain unread count in state, increment on new notification, use Context for app-wide access, show badge with count, clear on view, and persist preference to server.

---

### Q757: What's the advantage of webpack Module Federation for React microfrontends?

Share code across independently deployable apps, load remote components dynamically, version libraries independently, and coordinate at consumption time—enables true modular architecture.

---

### Q758: How to validate user input without form libraries in React?

Maintain validation state per field, validate on blur/change, show field-specific errors, provide clear feedback. Consider libraries like React Hook Form for complex forms.

---

### Q759: What are React's best practices for handling global keyboard shortcuts?

Create context/hook for registering shortcuts, prevent propagation to avoid conflicts, document all shortcuts, and allow user customization if possible.

---

### Q760: How to optimize React app for first input delay (FID)?

Split JS chunks, defer non-critical scripts, use requestIdleCallback for background work, minimize main thread work, and keep event handlers fast (< 100ms).

---

### Q761: What is the role of React's `useLayoutEffect` for DOM synchronization?

`useLayoutEffect` synchronously updates DOM before browser paint. Use for layout measurements, scroll position restoration, or DOM mutations requiring immediate effect.

---

### Q762: How to implement a search-as-you-type feature with debouncing?

Debounce search input with useRef/setTimeout, trigger fetch on term change, cache results, show results in dropdown, and highlight matches.

---

### Q763: What's the cost of unnecessary Fragment wrapping in React?

Fragments are free (not DOM nodes), but returning unnecessary Fragment components adds nesting. Use sparingly; avoid if not needed (except when returning multiple elements from map).

---

### Q764: How to handle screen reader announcements for dynamic form errors?

Use aria-live="polite" on error container, update text content (screen reader announces), use aria-invalid="true" on fields, and link aria-describedby to error messages.

---

### Q765: What are React's constraints for building low-latency multiplayer experiences?

React's batched updates introduce latency. Use UDP-based protocols (not TCP/HTTP), implement client-side prediction, server reconciliation, and consider native/game engines for critical features.

---

### Q766: How to implement efficient state synchronization across browser tabs?

Use localStorage/sessionStorage events, BroadcastChannel API for simpler cases, or service worker message passing. Avoid race conditions with timestamps or IDs.

---

### Q767: What is the purpose of React's `propTypes` for runtime validation?

propTypes validate props at runtime in development (removed in production builds). Catches type mismatches early. TypeScript replaces this in modern projects for compile-time safety.

---

### Q768: How to optimize bundle size of monorepo packages in React?

Tree-shake unused exports, share common dependencies via Yarn workspaces, use dynamic imports for rarely-used packages, and analyze each package separately.

---

### Q769: What's the advantage of Atomic Design methodology for React components?

Atomic Design (atoms → molecules → organisms) creates a scalable, reusable component library. Clear hierarchy makes testing, maintenance, and sharing components easier.

---

### Q770: How to implement a fair rate-limiting system for API calls in React?

Track request count with timestamps, reject if limit exceeded, implement exponential backoff, show user feedback about limits, and respect rate-limit headers from server.

---

### Q771: What are React's best practices for handling user preferences?

Store in localStorage for sync non-critical prefs, Context for runtime access, provide UI to change, sync with server on next request, and respect system preferences (dark mode, etc.).

---

### Q772: How to handle cross-cutting concerns in React without prop drilling?

Use Context for data/functions, custom hooks for shared logic, middleware for side effects, and higher-order functions for wrapping behavior.

---

### Q773: What is the cost of CSS-in-JS libraries for React?

Runtime overhead (parsing, injecting), larger bundle size. Mitigate with babel plugins (extract CSS), use static styling where possible, and consider CSS Modules as alternative.

---

### Q774: How to implement a role-based access control (RBAC) system in React?

Define roles with permissions, check permissions in Context, render components conditionally, disable/hide restricted features, and validate on server (security).

---

### Q775: What's the role of React's `useCallback` in optimization?

`useCallback` memoizes function reference, preventing unnecessary child re-renders when function passed as prop. Use when function passed to optimized (memo'd) children.

---

### Q776: How to optimize React component re-renders with Profiler?

Use React DevTools Profiler to identify slow components, check re-render reasons, apply memo/useMemo/useCallback as needed, and measure improvements.

---

### Q777: What are React's constraints for building progressive web apps (PWAs)?

Service worker management, offline support, manifest setup, installation prompts. Use Next.js PWA plugin or workbox for simplified integration.

---

### Q778: How to implement data-driven feature flags in React?

Fetch flags from server on app boot, store in Context, evaluate conditionally, update without restart via /actuator/refresh-like endpoint, and log feature usage.

---

### Q779: What is the relationship between React reconciliation and list order?

React matches elements by key (if provided) or position. Reordering without stable keys breaks state. Keys maintain identity, enabling correct state preservation.

---

### Q780: How to handle timezone-aware calendar components in React?

Store dates as UTC, display in user timezone, handle DST transitions, use date-fns/Day.js timezone plugin, and provide timezone selector if needed.

---

### Q781: What's the advantage of useCallback for event handlers?

`useCallback` memoizes handler, preventing new function on each render (breaks React.memo). Essential for handlers passed to memo'd children in lists or dynamic components.

---

### Q782: How to implement resilient API error recovery with React Query?

Use retry settings, implement backoff, handle specific error types with custom logic, use error boundaries, and show user-friendly error messages.

---

### Q783: What are React's best practices for managing form submission state?

Track loading/error/success states, disable submit button during submission, show feedback messages, handle server validation errors, and provide user confirmation for destructive actions.

---

### Q784: How to optimize React Lazy loading with preloading strategies?

Prefetch components on hover/route prediction, preload critical chunks in background, use requestIdleCallback, and measure impact on performance budgets.

---

### Q785: What is the cost of `useReducer` vs `useState`?

`useReducer` adds complexity (dispatch, action types) but scales better for complex state. `useState` simpler for independent state. Choose based on state complexity.

---

### Q786: How to implement a fair user-facing rate limiting UI in React?

Show remaining requests/quota, countdown timer until reset, suggest upgrade, provide batch operations, and cache results to minimize requests.

---

### Q787: What's the role of React's strict equality (===) in optimization?

React uses === for comparing values (primitives OK, objects/arrays need memoization). Understand reference equality to avoid unnecessary re-renders.

---

### Q788: How to handle animation cleanup in React when component unmounts?

Cancel in-flight animations in useEffect cleanup, cancel timers/timeouts, use AbortController for fetch, and test unmount cleanup thoroughly.

---

### Q789: What are React's constraints for building voice-activated interfaces?

Use Web Speech API, handle browser support differences, provide text fallback, ensure keyboard navigation works, and test with actual voice input for edge cases.

---

### Q790: How to optimize React app with intelligent code splitting?

Split by route, feature flags, or user roles. Preload critical chunks, prefetch likely routes, and measure impact on metrics (bundle size, TTI, LCP).

---

### Q791: What is the purpose of React's `key` for non-list components?

`key` can reset component state by causing unmount/remount. Use to trigger re-initialization (animations, data fetching) when key changes.

---

### Q792: How to implement a zero-configuration state management hook in React?

Use Zustand or Jotai for atomic, minimal state management. No Redux boilerplate; hooks directly access/update state with simple API.

---

### Q793: What's the advantage of semantic HTML over divitis in React?

Semantic tags (button, nav, menu) improve accessibility, SEO, and semantics. Screen readers understand structure. Avoid `<div>` soup; use proper elements when possible.

---

### Q794: How to handle cross-domain data loading in React safely?

Use CORS headers on server, validate origins, implement CSP headers, avoid storing secrets, use httpOnly cookies for auth, and validate response data types.

---

### Q795: What are React's best practices for handling race conditions in fetching?

Use AbortController, ignore stale responses, race condition detection (request ID), or React Query which handles internally. Test with slow networks simulated.

---

### Q796: How to implement a lazy evaluation pattern for expensive computations in React?

Use useMemo with dependencies, defer computation until needed, cache results, use Web Workers for CPU-intensive tasks, and avoid recomputation of unchanged data.

---

### Q797: What is the cost of inline event handlers in React?

Inline handlers create new function every render, potentially breaking React.memo. Move outside component or use useCallback to memoize for optimization.

---

### Q798: How to plan gradual migration from Class to Function Components in React?

Migrate component by component, cover with tests first, use Hooks for equivalent Class features, and handle refs/getDerivedStateFromProps carefully.

---

### Q799: What's the role of React's error boundary for async errors?

Error boundaries catch synchronous render errors only. Async errors from effects require try/catch or error state. Combine both for comprehensive error handling.

---

### Q800: How to optimize React app for long-term maintenance and team handoff?

Document patterns and decisions, enforce code style (ESLint), use TypeScript, create runbooks for common tasks, maintain changelog, and design for extensibility.

---

### Q801: What's the relationship between React component identity and key prop?

Components with different keys mount/unmount separately, resetting state. Use stable keys from data, not index (breaks on reorder). Key equality enables state preservation.

---

### Q802: How to implement a fair component sharing system in monorepo React?

Publish shared components to npm workspace, version independently, document per component, maintain backwards compatibility, and test across consuming apps.

---

### Q803: What are React's constraints for building inclusive typography systems?

Support dynamic sizing based on user preferences, respect prefers-reduced-motion, ensure readable font sizes (not too small), provide font loading strategy to avoid FOIT/FOUT, and test with screen readers.

---

### Q804: How to handle complex form state validation with schemas in React?

Use yup/zod/joi for schema validation, validate on blur/submit, show field and cross-field errors, provide clear feedback, and implement custom validators for domain logic.

---

### Q805: What is the cost of repeated object creation in React renders?

New objects/arrays break === equality even if values same, causing re-renders. Memoize objects with useMemo or move outside component to prevent recreation.

---

### Q806: How to implement efficient text truncation with tooltips in React?

Use CSS `text-overflow: ellipsis`, detect overflow with ref measurement, show tooltip on hover, and test with long text, RTL, and dynamic content.

---

### Q807: What's the advantage of viewport observations for lazy loading?

Intersection Observer API detects element visibility efficiently, avoiding scroll event thrashing. Ideal for lazy-loading images, infinite scroll, and performance tracking.

---

### Q808: How to optimize React app for users with slow devices?

Minimize JS, defer non-critical code, use images optimally (responsive, compressed), reduce animations, implement skeleton screens, and test on actual slow devices (Chrome DevTools handicap).

---

### Q809: What are React's best practices for managing side effects in order?

Compose multiple useEffect hooks for clarity, each handles single concern, dependencies control execution timing, use cleanup functions for teardown, and think in terms of synchronization not lifecycle.

---

### Q810: How to implement a resilient WebSocket connection in React?

Implement reconnect logic with exponential backoff, detect connection loss, queue messages during disconnect, sync state on reconnect, and show connection status.

---

### Q811: What is the purpose of React's `useMemo` dependencies array?

Dependencies control when memoized value is recalculated. Missing dependency causes stale values; extra dependencies cause unnecessary recalculation. Linter helps identify correct dependencies.

---

### Q812: How to handle image preloading strategies in React?

Preload critical images in head, prefetch likely images, use cdn.img tag with sizes, implement blur-up loading, and lazy-load below-fold images with Intersection Observer.

---

### Q813: What's the cost of Context provider re-renders in React?

Context value changes trigger all consumers to re-render. Mitigate by: memoizing value, splitting contexts by concern, or using atom-based libraries (Jotai, Zustand).

---

### Q814: How to implement a fair multi-select component in React?

Support keyboard navigation (arrow keys, space), show selected count, provide clear/select all buttons, handle large lists with virtualization, and test accessibility.

---

### Q815: What are React's constraints for building mobile-first responsive interfaces?

Consider touch targets (44px minimum), handle tap vs hover, avoid scroll locks, optimize for smaller viewports first, and test on actual devices (not just browser).

---

### Q816: How to optimize React app load time for poor network (3G)?

Code-split aggressively, preload critical chunks only, compress assets, serve from CDN, implement service worker for offline, and test with 3G Fast throttle.

---

### Q817: What is the relationship between React's virtual DOM and browser DOM?

Virtual DOM is in-memory representation. React reconciles changes, updates browser DOM minimally. Minimization improves performance significantly vs direct DOM manipulation.

---

### Q818: How to implement a resilient data export feature in React?

Generate in background (Web Worker), show progress, handle large datasets in chunks, provide stream download, and validate exported data format.

---

### Q819: What's the advantage of imperative animation libraries for React?

Framer Motion, React Spring enable complex orchestrated animations, keyframe coordination, and gesture responses. Cleaner than managing CSS animations manually.

---

### Q820: How to handle sensitive form data security in React?

Never log sensitive values, clear data on unmount, use autoComplete="off", avoid copying to clipboard automatically, validate server-side, and use HTTPS only.

---

### Q821: What are React's best practices for handling third-party script injection?

Load scripts asynchronously, avoid blocking render, use window global cautiously, integrate via Context for app-wide access, and verify script integrity (SRI).

---

### Q822: How to optimize React app CSS-in-JS with static extraction?

Use babel plugins (styled-components, emotion) to extract critical CSS, reduce runtime overhead, improve performance, and enable static optimization during build.

---

### Q823: What is the cost of `Array.map` re-creating components?

Each map call re-creates component instances if function defined inline. Move function outside or memoize for optimization. Use stable keys to preserve state.

---

### Q824: How to implement a fair carousel/slider component in React?

Support keyboard navigation (arrow keys), show active indicator, handle swipe on mobile, lazy-load slides, implement autoplay with pause on hover, and test with screen readers.

---

### Q825: What's the role of React's `useRef` for imperative operations?

`useRef` provides direct DOM access for imperative operations: focus, text selection, triggering animations. Use sparingly; prefer declarative props when possible.

---

### Q826: How to handle concurrent rendering in React applications?

React 18+ automatically schedules work based on priority. Use `useTransition` for deferrable updates, `useDeferredValue` for non-urgent data. Don't force concurrency; let React manage.

---

### Q827: What are React's constraints for implementing real-time audio/video features?

Use WebRTC for P2P, MediaStream API for capturing, handle permissions carefully, provide fallbacks, and ensure audio/video codecs compatibility across browsers.

---

### Q828: How to optimize React app for visual regression testing?

Use Percy/Chromatic for visual snapshots, test across breakpoints, handle dynamic content (disable animations), and establish diff thresholds to avoid noise.

---

### Q829: What is the purpose of React's `suppressHydrationWarning` prop?

Suppress warnings during server-render mismatch (e.g., timestamp server renders differently than client). Use sparingly; fix root cause when possible (e.g., useEffect for client-only values).

---

### Q830: How to implement a lazy-evaluated selector in Redux-like state?

Use `reselect` for memoization, compute derived state on demand, cache results, and avoid recreation on unchanged inputs for performance.

---

### Q831: What's the advantage of semantic versioning for React packages?

MAJOR.MINOR.PATCH: breaking changes require major version, backward-compatible features use minor, fixes use patch. Enables dependency management confidence.

---

### Q832: How to handle animation frame synchronization in React?

Use `requestAnimationFrame` for smooth animations, coordinate multiple animations with shared frame, and cleanup on unmount to prevent memory leaks.

---

### Q833: What are React's best practices for handling form autofill?

Ensure proper input name/autocomplete attributes, handle autofill lag with onAutoFill event, validate after autofill, and test autofill scenarios.

---

### Q834: How to optimize React app for CPU-constrained environments?

Reduce complexity, use CSS transforms, defer non-critical work (requestIdleCallback), profile to identify bottlenecks, and consider lower-interactive alternatives (static HTML).

---

### Q835: What is the cost of useCallback with many dependencies?

Each dependency change re-creates callback. Too many deps defeats purpose. Sign of component doing too much; consider splitting into smaller specialized components.

---

### Q836: How to implement a resilient clipboard paste feature in React?

Use Clipboard API, handle paste image/text, validate pasted data, show feedback, request permission if needed, and provide fallback for unsupported browsers.

---

### Q837: What's the role of React's `forwardRef` for accessing child DOMs?

`forwardRef` allows parent to access child DOM nodes via ref. Use for imperative operations (focus, scroll). Typically needed for library (input, video) or 3rd-party components.

---

### Q838: How to handle component state restoration after navigation in React Router?

Store state in URL query params, restore from URL on mount, use Context for temporary state, or implement custom store synchronized with URL.

---

### Q839: What are React's constraints for building data-heavy dashboards?

Render performance is critical. Use Canvas/SVG rendering, virtualize large lists, defer non-visible data loading, implement loading states, and profile aggressively.

---

### Q840: How to optimize React bundle for tree-shaking?

Use ES6 exports, avoid default exports (less shaking), mark side-effect-free modules with sideEffects: false in package.json, and analyze bundle with webpack-bundle-analyzer.

---

### Q841: What is the purpose of React's `<Suspense>` boundary?

Suspense catches promises thrown by components, shows fallback UI while loading, enables code splitting and data fetching coordination, and simplifies loading state management.

---

### Q842: How to implement fair notification stacking in React?

Maintain stack of notifications, position on screen, auto-dismiss with timeout, allow manual dismiss, and handle overflow (max visible count) with queue.

---

### Q843: What's the advantage of context-based animation syncing in React?

Synchronize animations across components via Context, coordinate timing, avoid prop drilling animation states, and enable global animation toggles for preference.

---

### Q844: How to handle secure session storage in React SPAs?

Use httpOnly cookies (secure, no JS access), avoid localStorage for sensitive tokens, implement token refresh on 401, and handle logout via server endpoint.

---

### Q845: What are React's best practices for responsive image loading?

Use srcset with media descriptors, picturepic for different image sources, lazy-load off-screen images, optimize with CDN, and test on various screen sizes.

---

### Q846: How to optimize React app for accessibility-first development?

Start with semantic HTML, test with keyboard/screen reader, use ARIA when needed, follow WCAG 2.1 AA, and include accessibility in code reviews.

---

### Q847: What is the cost of mutable state in React?

Mutable state bypasses React's reactivity, preventing re-renders. Always use setState/useState to trigger updates. Use Immer if mutations feel natural.

---

### Q848: How to implement a resilient long-polling mechanism in React?

Poll incrementally, backoff on error, detect stale data, show connection status, and switch to WebSocket if available for efficiency.

---

### Q849: What's the role of React's `useTransition` for async state updates?

`useTransition` marks updates as non-urgent, React deprioritizes, keeps current UI responsive. Show Suspense fallback while transitioning, improving UX.

---

### Q850: How to plan React component testing strategy for large projects?

Test behavior (not implementation), unit tests for logic, integration tests for components, E2E for user flows. Maintain test coverage (>80%), and automate in CI.

---

### Q851: What's the relationship between React's scheduler and task priority?

React's Fiber scheduler prioritizes work: user input (high), network response (medium), non-urgent (low). `useTransition` and `useDeferredValue` control priority for better UX.

---

### Q852: How to implement graceful degradation for unsupported features in React?

Check feature availability (navigator, window APIs), provide fallback UI, inform users of limitations, and test sans-feature scenarios thoroughly.

---

### Q853: What are React's constraints for building real-time multiplayer games?

React's render cycle too slow for game loops. Use separate game engine (Babylon.js, Three.js), React manages UI only. Separate graphics from logic.

---

### Q854: How to optimize React app for internationalized content delivery?

Lazy-load locale bundles, cache translations, CDN per region, handle RTL layouts, test with multiple languages, and provide language selector prominently.

---

### Q855: What is the cost of prop object creation in React render?

Creating new object literal in props every render breaks React.memo. Move outside component or useMemo. Impacts performance in lists with memoized items.

---

### Q856: How to implement a fair comment/discussion thread component in React?

Lazy-load comments, pagination, nested replies (limit depth), reply-to functionality, editing/deletion with optimistic updates, and handle notifications.

---

### Q857: What's the advantage of React Profiler for identifying bottlenecks?

Profiler shows per-component render times, re-render reasons, flame graph visualization. Identify slow components and optimize with data-driven approach.

---

### Q858: How to handle complex state machines in React?

Use xstate or similar state machine library, define transitions explicitly, implement guards (conditional transitions), and test state flows comprehensively.

---

### Q859: What are React's best practices for handling geolocation data?

Request permission, show loading state, handle denial gracefully, use latitude/longitude accurately, center map properly, and cache location (respect user privacy).

---

### Q860: How to optimize React app for progressive image loading?

Load low-res placeholder first, progressive JPEG, blur-up effect with CSS, replace with high-res on load, and handle slow network gracefully.

---

### Q861: What is the purpose of React's `useDebugValue` hook?

`useDebugValue` shows custom hook state in DevTools. Help debugging by formatting complex state for readability. Example: format state for easier inspection.

---

### Q862: How to implement resilient user session management in React?

Check session on app boot, refresh on 401, handle logout via server, show session expiry warning, and clear client state on logout.

---

### Q863: What's the cost of conditional rendering all branches in React?

Rendering conditional branches creates components even if hidden. Hide with CSS (display: none) for kept state, conditional render for fresh state. Choose based on use case.

---

### Q864: How to handle complex form submission flows in React?

Track submission state (idle, submitting, success, error), validate before submit, handle server errors, show loading/success/error states, and provide user feedback.

---

### Q865: What are React's constraints for building searchable, filterable lists?

Large lists need virtualization, debounced filtering, pagination, or infinite scroll. Implement server-side for scalability, client-side only for small datasets.

---

### Q866: How to optimize React app for Core Web Vitals (LCP, FID/INP, CLS)?

LCP: preload critical resources, optimize images. FID/INP: reduce JS execution, defer non-critical work. CLS: reserve space for ads/images, avoid unsized content.

---

### Q867: What is the relationship between React suspense and error boundaries?

Suspense catches promises (loading), Error Boundary catches errors. Combine both for complete error/loading handling. Suspense doesn't catch async errors.

---

### Q868: How to implement a resilient backup/restore feature in React?

Back up state periodically, compress and encrypt, restore with integrity check, show progress, and handle version mismatches during restore.

---

### Q869: What's the advantage of Atomic Components in design systems?

Breaking design into atoms (buttons, inputs) enables:
- Reusability across apps
- Consistency
- Isolation for testing
- Minimal dependencies
- Clear composition rules

---

### Q870: How to handle cross-browser compatibility for modern APIs in React?

Check feature availability, provide polyfills/fallbacks, test on target browsers, use feature detection (not user agent), and transpile for older browsers.

---

### Q871: What are React's best practices for managing loading states?

Explicit state for each async operation, show appropriate UI (loading, success, error), provide user feedback, and avoid cascading spinners (group related items).

---

### Q872: How to optimize React app database queries on client?

Minimize queries (batch), cache responses, implement pagination, lazy-load data, denormalize strategically, and delegate complex queries to server (GraphQL, API).

---

### Q873: What is the cost of inline callback functions in React?

Inline callbacks create new function instance every render, breaking React.memo and useCallback. Move outside or use useCallback for optimization.

---

### Q874: How to implement a fair data table with sorting/filtering in React?

Support multi-column sort, advanced filter UI, export functionality, pagination, lazy-load rows, and preserve sort/filter on page reload.

---

### Q875: What's the role of React's `startTransition` API for urgent updates?

`startTransition` manually mark updates as non-urgent, same effect as `useTransition` but outside components. Useful in event handlers for async operations.

---

### Q876: How to handle animation cleanup for unmounting React components?

Cancel animations in useEffect cleanup, clear timeouts/intervals, use AbortController for fetch requests during animations, and prevent state updates on unmounted components.

---

### Q877: What are React's constraints for building real-time collaboration features?

Handle concurrent edits (OT/CRDT), sync efficiently, merge changes from multiple users, show presence awareness, and handle connection loss gracefully.

---

### Q878: How to optimize React Performance with dynamic imports?

Use dynamic() with Next.js, React.lazy() for code-split, prefetch likely chunks, measure impact on time-to-interactive, and avoid splitting too many chunks.

---

### Q879: What is the purpose of React Query's `staleTime` and `cacheTime`?

`staleTime`: how long data considered fresh before refetch. `cacheTime`: how long to keep unused data before garbage collection. Balance freshness and performance.

---

### Q880: How to implement a fair search with AI/ML suggestions in React?

Use ML service for suggestions, cache/dedupe requests, rank suggestions by relevance, show confidence scores, allow feedback for ranking improvement.

---

### Q881: What's the advantage of Component Composition over Class Inheritance?

Composition (building with smaller components) is more flexible, easier to test, avoids deep inheritance chains, and aligns with React's design philosophy.

---

### Q882: How to handle user input sanitization in React?

Never trust user input, sanitize with DOMPurify for HTML, escape in event handlers, validate on server (critical), use parameterized queries server-side.

---

### Q883: What are React's best practices for managing deeply-nested state?

Normalize state structure (flat), use reducers for complex updates, leverage Immer for mutable-like syntax, split into multiple hooks/contexts per concern.

---

### Q884: How to optimize React app for low JavaScript execution budgets?

Prioritize critical rendering path, defer non-critical JS, use service workers for caching, minimize bundle, and test with DevTools throttling.

---

### Q885: What is the cost of useCallback with no dependencies?

`useCallback` with [] creates function once, always stable reference. Useful but not necessary if function not passed to children (no memo benefit).

---

### Q886: How to implement a resilient file storage system in React?

Chunk uploads for reliability, validate server-side, implement resumable uploads, backup to cloud, show storage usage, and handle quotas gracefully.

---

### Q887: What's the role of React's `useId` hook?

`useId` generates unique IDs for form elements, avoiding conflicts between components. Useful for accessibility (aria-labelledby), form association, and server rendering.

---

### Q888: How to handle complex navigation state in React Router?

Use location state for transitional data, param for persistent state, query string for filtering, preserve state on back navigation with history.

---

### Q889: What are React's constraints for building data-intensive analytics dashboards?

Performance critical. Use Canvas/SVG libraries, virtualize large tables, defer non-visible data, implement sampling for large datasets, and profile aggressively.

---

### Q890: How to optimize React app for progressive disclosure UIs?

Use expand/collapse components, lazy-load detailed content, maintain expand state per item, and consider performance of large expanded sections.

---

### Q891: What is the relationship between React Fiber and async rendering?

Fiber enables incremental rendering, pausing between renders to allow browser to handle input/animation. Fiber scheduler manages priority automatically.

---

### Q892: How to implement a resilient plugin/extension system in React?

Define plugin interface, lazy-load plugins dynamically, isolate plugin errors with error boundary, provide plugin hooks for lifecycle events.

---

### Q893: What's the advantage of React Hooks for logic reuse over render props/HOCs?

Hooks are simpler to write and read, avoid nesting/prop drilling, compose naturally, and integrate with other hooks without special handling.

---

### Q894: How to handle complex accessibility scenarios in React apps?

Test with actual screen readers, keyboard navigation throughout, ARIA when semantic HTML insufficient, focus management on dynamic updates, and user feedback loops.

---

### Q895: What are React's best practices for versioning component APIs?

Document breaking changes, provide migration guides, deprecate gradually, maintain old versions for time, and use semantic versioning for clarity.

---

### Q896: How to optimize React app for memory-constrained environments?

Lazy-load large data, implement pagination, use streams for processing, avoid storing entire datasets, monitor memory usage, and test on low-memory devices.

---

### Q897: What is the cost of derived state in React?

Derived state (computed from props) can lead to stale values. Calculate on render instead or use useMemo. Avoid storing values that can be computed.

---

### Q898: How to implement a resilient feedback/survey collection system in React?

Validate responses, save locally (offline-first), retry sending, handle network failures, provide confirmation, and ensure privacy/security of responses.

---

### Q899: What's the role of React's `children` prop in component design?

`children` enables composition, slot-based layouts, and flexible rendering. Prefer children over render props for simple cases; supports multiple/mixed content types.

---

### Q900: How to plan complete React app migration from legacy code to modern patterns?

Audit existing codebase, prioritize high-impact areas (bottlenecks, frequently changed), incremental migration component-by-component, test thoroughly, document patterns, and train team on new approaches.

