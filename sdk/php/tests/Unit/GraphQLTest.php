<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TrafficTwin\Sanitizer\GraphQL;

/** Shape of a GraphQL document (sanitizer.md 5.7.1) and the name rule; the vectors cover the integration. */
final class GraphQLTest extends TestCase
{
    /** @return iterable<string, array{string, array{0: string, 1: bool}|null}> */
    public static function shapes(): iterable
    {
        yield 'named query' => ['query GetOrder($id: ID!) { order(id: $id) { id status items { sku } } }', ['query GetOrder($id:ID!){order(id:$id){id status items{sku}}}', false]];
        yield 'inline literals' => ['{ order(id: "ORD-123", n: 5, r: 1.5, ok: true, st: SHIPPED, x: null) { id } }', ['{order(id:?s n:?i r:?f ok:?b st:?e x:?n){id}}', false]];
        yield 'mutation, fragment' => ['mutation M($in: [OrderIn!]! = [{note: "urgente"}]) { a: create(in: $in) { ...F } } fragment F on Order { id }', ['mutation M($in:[OrderIn!]!=[{note:?s}]){a:create(in:$in){...F}}fragment F on Order{id}', false]];
        yield 'collapsed alias' => ['{ o4821553: order(id: 1) { id } }', ['{*:order(id:?i){id}}', false]];
        yield 'bom, commas, comment' => ["\u{FEFF}{ a , b # c\n }", ['{a b}', false]];
        yield 'block string' => ['{ a(t: """x \""" y""") }', ['{a(t:?s)}', false]];
        yield 'introspection' => ['query IntrospectionQuery { __schema { types { name } } __typename }', ['query IntrospectionQuery{__schema{types{name}}__typename}', true]];
        yield 'aliased introspection' => ['{ __schema: order(id: 1) { id } }', ['{__schema:order(id:?i){id}}', false]];
        yield 'spread at root' => ['{ ...F } fragment F on Query { __schema { a } }', ['{...F}fragment F on Query{__schema{a}}', false]];
        yield 'not a document' => ['ciao', null];
        yield 'type definition' => ['type Query { a: Int }', null];
        yield 'leading zero' => ['{ a(x: 01) }', null];
        yield 'number then name' => ['{ a(x: 1abc) }', null];
        yield 'bad escape' => ['{ a(x: "\q") }', null];
        yield 'empty selection' => ['{ }', null];
        yield 'unbalanced' => ['{ a }}', null];
        yield 'nesting 64' => [str_repeat('{a', 64) . str_repeat('}', 64), [str_repeat('{a', 64) . str_repeat('}', 64), false]];
        yield 'nesting 65' => [str_repeat('{a', 65) . str_repeat('}', 65), null];
        yield 'too long' => ['{' . str_repeat('a ', 16384) . '}', null];
    }

    /** @param array{0: string, 1: bool}|null $want */
    #[DataProvider('shapes')]
    public function testShape(string $src, ?array $want): void
    {
        self::assertSame($want, GraphQL::shape($src));
    }

    public function testNameRule(): void
    {
        self::assertTrue(GraphQL::nameSafe('OrderStatus'));
        self::assertTrue(GraphQL::nameSafe('p_48215'));
        self::assertFalse(GraphQL::nameSafe('p_482155'));
        self::assertFalse(GraphQL::nameSafe('deadbeefdeadbeef'));
        self::assertTrue(GraphQL::nameSafe('deadbeefdeadbee'));
        self::assertFalse(GraphQL::nameSafe(str_repeat('a', 65)));
        self::assertFalse(GraphQL::nameSafe('1abc'));
        self::assertFalse(GraphQL::nameSafe('a-b'));
        self::assertFalse(GraphQL::nameSafe(''));
    }
}
