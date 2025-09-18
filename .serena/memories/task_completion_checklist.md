# Task Completion Checklist for FLEXT Auth

## Before Starting Any Task
1. **Read Current Code**: Always read the file before making changes
2. **Run Quality Checks**: Execute `make validate` to see current state
3. **Understand Context**: Check imports, dependencies, and patterns

## During Development
1. **Follow FLEXT Patterns**: Use flext-core patterns consistently
2. **Maintain Type Safety**: No Any types, proper type annotations
3. **Update Docstrings**: Ensure PEP8 compliance
4. **Test Changes**: Run relevant tests after each change

## After Each Change
1. **Run Linting**: `poetry run ruff check src`
2. **Run Type Check**: `poetry run mypy src --strict`
3. **Run Tests**: `poetry run pytest tests/ -v`
4. **Check Security**: `poetry run bandit -r src`

## Final Validation
1. **Complete Validation**: `make validate`
2. **All Tests Pass**: No failing tests
3. **No Security Issues**: Clean bandit report
4. **No Type Errors**: Clean mypy report
5. **No Lint Issues**: Clean ruff report

## Production Readiness Checklist
- [ ] All imports are direct and standardized
- [ ] All docstrings follow PEP8 standard
- [ ] No Any types in code
- [ ] No type: ignore hints
- [ ] No wrappers or compatibility layers
- [ ] No legacy functions
- [ ] No incomplete/mock/test code in src/
- [ ] All QA checks pass
- [ ] Security issues resolved
- [ ] Tests pass with good coverage