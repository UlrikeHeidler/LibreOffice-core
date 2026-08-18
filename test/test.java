package com.example;

import java.util.Set;

public class CSharpKeywords {

    private static final Set<String> CSHARP_KEYWORDS = Set.of(
        "abstract", "as", "base", "bool", "break", "byte",
        "case", "catch", "char", "checked",
        "class", "const", "continue", "decimal", "default",
        "delegate", "do", "double", "else",
        "enum", "event", "explicit", "extern", "false",
        "finally", "fixed", "float", "for",
        "foreach", "goto", "if", "implicit", "in",
        "int", "interface", "internal", "is", "lock"
    );

    public static boolean isCSharpKeyword(String word) {
        return CSHARP_KEYWORDS.contains(word);
    }

    public static void main(String[] args) {
        System.out.println(isCSharpKeyword("class"));   // true
        System.out.println(isCSharpKeyword("hello"));   // false
    }
}
